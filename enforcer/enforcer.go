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

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/rode/enforcer-k8s/config"
	rode "github.com/rode/rode/proto/v1alpha1"
	"go.uber.org/zap"
	v1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
)

type Enforcer struct {
	config *config.Config
	logger *zap.Logger
	rode   rode.RodeClient
}

func NewEnforcer(
	logger *zap.Logger,
	config *config.Config,
	rode rode.RodeClient,
) *Enforcer {
	return &Enforcer{
		config,
		logger,
		rode,
	}
}

var (
	getImageManifest    = remote.Image
	remoteWithTransport = remote.WithTransport
	insecureTransport   = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
)

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
		log.Error("error unmarshalling pod", zap.Error(err))
		return response, nil
	}

	for _, container := range pod.Spec.Containers {
		if pass := e.evaluatePolicy(log, response, container.Image); !pass {
			return response, nil
		}
	}

	response.Allowed = true

	return response, nil
}

func (e *Enforcer) evaluatePolicy(log *zap.Logger, response *v1.AdmissionResponse, imageName string) bool {
	log = log.With(zap.String("image", imageName))
	ref, err := name.ParseReference(imageName)
	if err != nil {
		handleError(log, response, "error parsing image reference", err)
		return false
	}

	var remoteOptions []remote.Option
	if e.config.RegistryInsecureSkipVerify {
		remoteOptions = append(remoteOptions, remoteWithTransport(insecureTransport))
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

	imageResourceUri := ref.Context().Digest(digest.String()).String()

	log.Debug("evaluating policy against image", zap.String("resourceUri", imageResourceUri))

	res, err := e.rode.EvaluatePolicy(context.Background(), &rode.EvaluatePolicyRequest{
		Policy:      e.config.PolicyId,
		ResourceUri: imageResourceUri,
	})

	if err != nil {
		handleError(log, response, "error evaluating policy", err)
		return false
	}

	if res.Pass {
		return true
	}

	log.Info("policy evaluation failed", zap.Any("result", res.Result))
	policyName := e.getPolicyName(log)

	response.Result = &metav1.Status{
		Message: fmt.Sprintf(`container image "%s" failed the Rode policy "%s" (id: %s)`, ref.Name(), policyName, e.config.PolicyId),
	}

	return false
}

func (e *Enforcer) getPolicyName(log *zap.Logger) string {
	policy, err := e.rode.GetPolicy(context.Background(), &rode.GetPolicyRequest{
		Id: e.config.PolicyId,
	})

	if err != nil {
		log.Error("failed to retrieve policy", zap.Error(err))
		return ""
	}

	return policy.GetPolicy().Name
}

func handleError(log *zap.Logger, response *v1.AdmissionResponse, message string, err error) {
	log.Error("message", zap.Error(err))

	response.Result = &metav1.Status{
		Message: fmt.Sprintf("%s: %s", message, err),
	}
}
