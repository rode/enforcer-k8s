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
	"net/http"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

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
	getImageManifest = remote.Image
)

func (e *Enforcer) Enforce(admissionReview *v1.AdmissionReview) (*v1.AdmissionResponse, error) {
	log := e.logger.Named("Enforce")

	response := &v1.AdmissionResponse{
		UID:     admissionReview.Request.UID,
		Allowed: true,
	}

	objectKind := admissionReview.Request.Kind.Kind
	if objectKind != "Pod" {
		return response, nil
	}

	var pod corev1.Pod
	if err := json.Unmarshal(admissionReview.Request.Object.Raw, &pod); err != nil {
		log.Error("error unmarshalling pod", zap.Error(err))
		response.Allowed = false
		return response, nil
	}

	insecure := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	for _, container := range pod.Spec.Containers {
		ref, err := name.ParseReference(container.Image)
		if err != nil {
			log.Error("error parsing image reference", zap.Error(err), zap.String("image", container.Image))
			response.Allowed = false
			return response, nil
		}

		img, err := getImageManifest(ref, remote.WithTransport(insecure))
		if err != nil {
			log.Error("error fetching image", zap.Error(err), zap.String("image", container.Image))
			response.Allowed = false
			return response, nil
		}

		digest, err := img.Digest()
		if err != nil {
			log.Error("error calculating digest", zap.Error(err), zap.String("image", container.Image))
			response.Allowed = false
			return response, nil
		}

		imageResourceUri := ref.Context().Digest(digest.String()).String()

		log.Debug("evaluating policy against image", zap.String("image", imageResourceUri))

		res, err := e.rode.EvaluatePolicy(context.Background(), &rode.EvaluatePolicyRequest{
			Policy:      e.config.PolicyId,
			ResourceUri: imageResourceUri,
		})

		if err != nil {
			log.Error("error evaluating policy", zap.Error(err))
			response.Allowed = false
			return response, nil
		}

		if !res.Pass {
			log.Info("policy evaluation failed", zap.Any("result", res.Result))
			response.Allowed = false
			return response, nil
		}
	}

	return response, nil
}
