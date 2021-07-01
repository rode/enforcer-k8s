// Copyright 2021 The Rode Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package enforcer

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	registryv1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/rode/enforcer-k8s/config"
	rode "github.com/rode/rode/proto/v1alpha1"
	"go.uber.org/zap"
	v1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
)

type Enforcer struct {
	config *config.Config
	logger *zap.Logger
	k8s    kubernetes.Interface
	rode   rode.RodeClient
}

func NewEnforcer(
	logger *zap.Logger,
	config *config.Config,
	k8s kubernetes.Interface,
	rode rode.RodeClient,
) *Enforcer {
	return &Enforcer{
		config,
		logger,
		k8s,
		rode,
	}
}

var (
	getImageManifest    = remote.Image
	remoteWithTransport = remote.WithTransport
	remoteWithAuth      = remote.WithAuth
	insecureTransport   = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
)

const (
	defaultNamespace             = "library"
	registryCredentialSecretType = "kubernetes.io/dockerconfigjson"
	registryCredentialDataKey    = ".dockerconfigjson"
)

type registryCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type imagePullSecret struct {
	Authentication map[string]*registryCredentials `json:"auths"`
}

func (e *Enforcer) Enforce(admissionReview *v1.AdmissionReview) (*v1.AdmissionResponse, error) {
	log := e.logger.Named("Enforce")

	response := &v1.AdmissionResponse{
		UID:     admissionReview.Request.UID,
		Allowed: false,
	}

	objectKind := admissionReview.Request.Kind.Kind
	if objectKind != "Pod" {
		response.Allowed = true
		return response, nil
	}

	var pod corev1.Pod
	if err := json.Unmarshal(admissionReview.Request.Object.Raw, &pod); err != nil {
		handleError(log, response, "error unmarshalling pod", err)
		return response, nil
	}

	var allContainers []corev1.Container
	allContainers = append(allContainers, pod.Spec.InitContainers...)
	allContainers = append(allContainers, pod.Spec.Containers...)

	pullSecrets, err := e.fetchImagePullSecrets(&pod)
	if err != nil {
		handleError(log, response, "error fetching image pull secrets", err)
		return response, nil
	}

	for _, container := range allContainers {
		if pass := e.evaluatePolicy(log, response, container.Image, pullSecrets); !pass {
			return response, nil
		}
	}

	response.Allowed = true

	return response, nil
}

func (e *Enforcer) fetchImagePullSecrets(pod *corev1.Pod) ([]*imagePullSecret, error) {
	var pullSecrets []*imagePullSecret

	for _, pullSecret := range pod.Spec.ImagePullSecrets {
		k8sSecret, err := e.k8s.CoreV1().Secrets(pod.Namespace).Get(context.Background(), pullSecret.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("error fetching image pull secret: %s", err)
		}

		if k8sSecret.Type != registryCredentialSecretType {
			return nil, fmt.Errorf("invalid secret type for %s (expected %s, got %s)", pullSecret.Name, registryCredentialSecretType, k8sSecret.Type)
		}

		data, ok := k8sSecret.Data[registryCredentialDataKey]
		if !ok {
			return nil, fmt.Errorf("missing key %s in image pull secret %s", registryCredentialDataKey, pullSecret.Name)
		}

		secret := &imagePullSecret{}
		if err := json.Unmarshal(data, secret); err != nil {
			return nil, fmt.Errorf("error unmarshalling image pull secret: %s", err)
		}

		// ensure that the auth keys are simply the hostname, to account for instances where a scheme or path is set
		// for example, the Docker Hub auth key is "https://index.docker.io/v1/", but "index.docker.io" is the registry name from the image
		secret, err = rewriteAuthKeys(secret)
		if err != nil {
			return nil, fmt.Errorf("error rewriting auth keys in secret: %s", err)
		}

		pullSecrets = append(pullSecrets, secret)
	}

	return pullSecrets, nil
}

func (e *Enforcer) evaluatePolicy(log *zap.Logger, response *v1.AdmissionResponse, imageName string, pullSecrets []*imagePullSecret) bool {
	ctx := context.Background()
	log = log.With(zap.String("image", imageName)).With(zap.String("policy group", e.config.PolicyGroup))
	ref, err := name.ParseReference(imageName)
	if err != nil {
		handleError(log, response, "error parsing image reference", err)
		return false
	}

	var remoteOptions []remote.Option
	if e.config.RegistryInsecureSkipVerify {
		remoteOptions = append(remoteOptions, remoteWithTransport(insecureTransport))
	}

	for _, c := range pullSecrets {
		if s, ok := c.Authentication[ref.Context().RegistryStr()]; ok {
			log.Debug("adding credentials to manifest request")
			remoteOptions = append(remoteOptions, remoteWithAuth(&authn.Basic{
				Username: s.Username,
				Password: s.Password,
			}))
		}
	}

	img, err := getImageManifest(ref, remoteOptions...)
	if err != nil {
		handleError(log, response, "error fetching image manifest", err)
		return false
	}

	digest, err := img.Digest()
	if err != nil {
		handleError(log, response, "error calculating digest", err)
		return false
	}

	imageResourceUri := createResourceUri(ref, digest)

	log.Debug("evaluating policy against image", zap.String("resourceUri", imageResourceUri))

	res, err := e.rode.EvaluateResource(ctx, &rode.ResourceEvaluationRequest{
		PolicyGroup: e.config.PolicyGroup,
		ResourceUri: imageResourceUri,
		Source: &rode.ResourceEvaluationSource{
			Name: e.config.Name,
		},
	})
	if err != nil {
		handleError(log, response, "error evaluating policy", err)
		return false
	}

	if res.ResourceEvaluation.Pass {
		return true
	}

	evaluationSummary, err := e.getEvaluationSummary(ctx, ref.Name(), res)
	if err != nil {
		handleError(log, response, "error getting evaluation summary", err)
		return false
	}

	response.Result = &metav1.Status{
		Message: evaluationSummary,
	}

	return false
}

func (e *Enforcer) getEvaluationSummary(ctx context.Context, imageName string, resourceEvaluationResult *rode.ResourceEvaluationResult) (string, error) {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf(`container image "%s" %s evaluation against the rode policy group "%s": `, imageName, policyResult(resourceEvaluationResult.ResourceEvaluation.Pass), resourceEvaluationResult.ResourceEvaluation.PolicyGroup))

	for i, policyEvaluation := range resourceEvaluationResult.PolicyEvaluations {
		policy, err := e.rode.GetPolicy(ctx, &rode.GetPolicyRequest{
			Id: policyEvaluation.PolicyVersionId,
		})
		if err != nil {
			return "", err
		}

		sb.WriteString(fmt.Sprintf(`policy "%s" %s`, policy.Name, strings.ToUpper(policyResult(policyEvaluation.Pass))))

		if i != len(resourceEvaluationResult.PolicyEvaluations)-1 {
			sb.WriteString(" | ")
		}
	}

	sb.WriteString("\n")

	return sb.String(), nil
}

func policyResult(passed bool) string {
	if passed {
		return "passed"
	}

	return "failed"
}

func handleError(log *zap.Logger, response *v1.AdmissionResponse, message string, err error) {
	log.Error(message, zap.Error(err))

	response.Result = &metav1.Status{
		Message: fmt.Sprintf("%s: %s", message, err),
	}
}

func createResourceUri(ref name.Reference, digest registryv1.Hash) string {
	image := ref.Context().Digest(digest.String()).String()
	image = strings.TrimPrefix(image, name.DefaultRegistry+"/")

	return strings.TrimPrefix(image, defaultNamespace+"/")
}

func rewriteAuthKeys(originalSecret *imagePullSecret) (*imagePullSecret, error) {
	secretWithHostnameKey := &imagePullSecret{
		Authentication: map[string]*registryCredentials{},
	}

	for k, v := range originalSecret.Authentication {
		u, err := url.ParseRequestURI(k)
		if err != nil {
			return nil, fmt.Errorf("error parsing registry url: %s", err)
		}

		value := v
		secretWithHostnameKey.Authentication[u.Host] = value
	}

	return secretWithHostnameKey, nil
}
