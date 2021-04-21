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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang/mock/gomock"
	"github.com/google/go-containerregistry/pkg/name"
	registryv1 "github.com/google/go-containerregistry/pkg/v1"
	registryfake "github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/rode/enforcer-k8s/config"
	"github.com/rode/enforcer-k8s/mocks"
	rode "github.com/rode/rode/proto/v1alpha1"
	v1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var _ = Describe("Enforcer", func() {
	var (
		policyId string
		ctx      context.Context
		conf     *config.Config
		enforcer *Enforcer
		mockRode *mocks.MockRodeClient
		mockCtrl *gomock.Controller
	)

	BeforeEach(func() {
		policyId = fake.UUID()
		conf = &config.Config{PolicyId: policyId}
		mockCtrl = gomock.NewController(GinkgoT())
		mockRode = mocks.NewMockRodeClient(mockCtrl)

		enforcer = NewEnforcer(
			logger,
			conf,
			mockRode,
		)
		ctx = context.Background()
	})

	AfterEach(func() {
		mockCtrl.Finish()
	})

	Describe("Enforce", func() {
		var (
			expectedUid     types.UID
			expectedImage   *registryfake.FakeImage
			expectedDigest  string
			admissionReview *v1.AdmissionReview
			actualResponse  *v1.AdmissionResponse
			actualError     error
		)

		BeforeEach(func() {
			expectedUid = types.UID(fake.UUID())
			expectedDigest = fake.LetterN(10)
			expectedImage = &registryfake.FakeImage{}
			expectedImage.DigestReturns(registryv1.Hash{
				Algorithm: "sha256",
				Hex:       expectedDigest,
			}, nil)

			getImageManifest = func(ref name.Reference, options ...remote.Option) (registryv1.Image, error) {
				return expectedImage, nil
			}

			admissionReview = &v1.AdmissionReview{
				Request: &v1.AdmissionRequest{
					Kind: metav1.GroupVersionKind{
						Kind: "Pod",
					},
					UID: expectedUid,
				},
			}

			admissionReview.Request.Object.Raw = createPodBody("harbor.localhost/rode-demo/nginx:latest")
		})

		JustBeforeEach(func() {
			actualResponse, actualError = enforcer.Enforce(admissionReview)
		})

		Describe("successful policy evaluation", func() {
			BeforeEach(func() {
				expectedRequest := &rode.EvaluatePolicyRequest{
					Policy:      policyId,
					ResourceUri: "harbor.localhost/rode-demo/nginx@sha256:" + expectedDigest,
				}
				mockRode.EXPECT().
					EvaluatePolicy(ctx, expectedRequest).Times(1).
					Return(&rode.EvaluatePolicyResponse{Pass: true}, nil)
			})

			When("a pod has a single container that passes policy", func() {
				It("should allow the request", func() {
					Expect(actualResponse.Allowed).To(BeTrue())
				})

				It("should include the request UID in the response", func() {
					Expect(actualResponse.UID).To(Equal(expectedUid))
				})

				It("should not return an error", func() {
					Expect(actualError).To(BeNil())
				})
			})

			When("the enforcer is configured not to verify TLS certificates against container registries", func() {
				var actualTransport *http.Transport

				BeforeEach(func() {
					conf.RegistryInsecureSkipVerify = true
					remoteWithTransport = func(t http.RoundTripper) remote.Option {
						if transport, ok := t.(*http.Transport); ok {
							actualTransport = transport
						}

						return remote.WithTransport(t)
					}
				})

				It("should pass an insecure http.Transport", func() {
					Expect(actualTransport).NotTo(BeNil())
					Expect(actualTransport.TLSClientConfig.InsecureSkipVerify).To(BeTrue())
				})
			})
		})

		When("the image name cannot be parsed", func() {
			BeforeEach(func() {
				admissionReview.Request.Object.Raw = createPodBody("invalid@foo")
			})

			It("should deny the request", func() {
				Expect(actualResponse.Allowed).To(BeFalse())
			})

			It("should not return an error", func() {
				Expect(actualError).NotTo(HaveOccurred())
			})
		})

		When("an error occurs fetching the image manifest", func() {
			BeforeEach(func() {
				getImageManifest = func(ref name.Reference, options ...remote.Option) (registryv1.Image, error) {
					return nil, errors.New(fake.Word())
				}
			})

			It("should deny the request", func() {
				Expect(actualResponse.Allowed).To(BeFalse())
			})

			It("should not return an error", func() {
				Expect(actualError).NotTo(HaveOccurred())
			})
		})

		When("an error occurs calculating the image digest", func() {
			BeforeEach(func() {
				expectedImage.DigestReturns(registryv1.Hash{}, errors.New(fake.Word()))
			})

			It("should deny the request", func() {
				Expect(actualResponse.Allowed).To(BeFalse())
			})

			It("should not return an error", func() {
				Expect(actualError).NotTo(HaveOccurred())
			})
		})

		When("the container image fails policy", func() {
			var (
				expectedPolicyName string
			)

			BeforeEach(func() {
				expectedPolicyName = fake.Word()
				mockRode.EXPECT().
					EvaluatePolicy(gomock.Any(), gomock.Any()).
					Return(&rode.EvaluatePolicyResponse{Pass: false}, nil)

				mockRode.EXPECT().
					GetPolicy(ctx, &rode.GetPolicyRequest{Id: policyId}).
					Return(&rode.Policy{Policy: &rode.PolicyEntity{Name: expectedPolicyName}}, nil)
			})

			It("should deny the request with a message", func() {
				Expect(actualResponse.Allowed).To(BeFalse())
				Expect(actualResponse.Result.Message).To(ContainSubstring(fmt.Sprintf(`failed the Rode policy "%s"`, expectedPolicyName)))
			})

			It("should not return an error", func() {
				Expect(actualError).NotTo(HaveOccurred())
			})
		})

		When("the container image fails policy and retrieving the policy name fails", func() {
			BeforeEach(func() {
				mockRode.EXPECT().
					EvaluatePolicy(gomock.Any(), gomock.Any()).
					Return(&rode.EvaluatePolicyResponse{Pass: false}, nil)

				mockRode.EXPECT().
					GetPolicy(ctx, &rode.GetPolicyRequest{Id: policyId}).
					Return(nil, errors.New(fake.Word()))
			})

			It("should deny the request with a message", func() {
				Expect(actualResponse.Allowed).To(BeFalse())
				Expect(actualResponse.Result.Message).To(ContainSubstring("failed the Rode policy"))
			})

			It("should not return an error", func() {
				Expect(actualError).NotTo(HaveOccurred())
			})
		})

		When("an init container fails policy", func() {
			var (
				initContainerImage string
			)

			BeforeEach(func() {
				initContainerImage = "harbor.localhost/rode-demo/pause"
				pod := corev1.Pod{
					Spec: corev1.PodSpec{
						InitContainers: []corev1.Container{
							{
								Image: initContainerImage,
							},
						},
						Containers: []corev1.Container{
							{
								Image: "harbor.localhost/rode-demo/nginx:latest",
							},
						},
					},
				}

				data, err := json.Marshal(pod)
				Expect(err).NotTo(HaveOccurred())

				admissionReview.Request.Object.Raw = data

				mockRode.EXPECT().
					GetPolicy(ctx, &rode.GetPolicyRequest{Id: policyId}).
					Return(&rode.Policy{Policy: &rode.PolicyEntity{Name: fake.Word()}}, nil)

				mockRode.
					EXPECT().
					EvaluatePolicy(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, r *rode.EvaluatePolicyRequest) (*rode.EvaluatePolicyResponse, error) {
						return &rode.EvaluatePolicyResponse{
							Pass: !strings.Contains(r.ResourceUri, initContainerImage),
						}, nil
					}).
					AnyTimes()
			})

			It("should deny the request", func() {
				Expect(actualResponse.Allowed).To(BeFalse())
				Expect(actualResponse.Result.Message).To(ContainSubstring(initContainerImage))
			})
		})

		When("an error occurs calling Rode", func() {
			var expectedError string
			BeforeEach(func() {
				expectedError = fake.Word()
				mockRode.EXPECT().
					EvaluatePolicy(gomock.Any(), gomock.Any()).
					Return(nil, errors.New(expectedError))
			})

			It("should deny the response with a message", func() {
				Expect(actualResponse.Allowed).To(BeFalse())
				Expect(actualResponse.Result.Message).To(ContainSubstring(expectedError))
			})

			It("should not return an error", func() {
				Expect(actualError).To(BeNil())
			})
		})

		When("the object is not a pod", func() {
			BeforeEach(func() {
				admissionReview.Request.Kind.Kind = fake.Word()
				mockRode.EXPECT().EvaluatePolicy(gomock.Any(), gomock.Any()).Times(0)
			})

			It("should allow the request", func() {
				Expect(actualResponse.Allowed).To(BeTrue())
			})

			It("should not return an error", func() {
				Expect(actualError).NotTo(HaveOccurred())
			})
		})

		When("the raw object response is invalid", func() {
			BeforeEach(func() {
				admissionReview.Request.Object.Raw = []byte("}{")
			})

			It("should deny the request", func() {
				Expect(actualResponse.Allowed).To(BeFalse())
			})

			It("should not return an error", func() {
				Expect(actualError).NotTo(HaveOccurred())
			})
		})
	})
})

func createPodBody(image string) []byte {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Image: image,
				},
			},
		},
	}

	data, err := json.Marshal(pod)
	Expect(err).NotTo(HaveOccurred())

	return data
}
