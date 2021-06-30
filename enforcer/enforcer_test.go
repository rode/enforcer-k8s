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
	"google.golang.org/grpc"
	"net/http"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
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
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

var _ = Describe("Enforcer", func() {
	var (
		expectedPolicyId string
		conf             *config.Config
		enforcer         *Enforcer
		mockRode         *mocks.FakeRodeClient
		mockK8sClient    = k8sfake.NewSimpleClientset()
	)

	BeforeEach(func() {
		expectedPolicyId = fake.UUID()
		conf = &config.Config{PolicyId: expectedPolicyId}
		mockRode = &mocks.FakeRodeClient{}

		enforcer = NewEnforcer(
			logger,
			conf,
			mockK8sClient,
			mockRode,
		)
	})

	Describe("Enforce", func() {
		var (
			actualResponse *v1.AdmissionResponse
			actualError    error

			expectedEvaluatePolicyResponse *rode.EvaluatePolicyResponse
			expectedEvaluatePolicyError    error

			expectedPolicyName     string
			expectedPolicy         *rode.Policy
			expectedGetPolicyError error

			expectedUid         types.UID
			expectedImage       *registryfake.FakeImage
			expectedDigest      string
			expectedResourceUri string
			admissionReview     *v1.AdmissionReview
		)

		BeforeEach(func() {
			expectedUid = types.UID(fake.UUID())
			expectedDigest = fake.LetterN(10)
			expectedResourceUri = "harbor.localhost/rode-demo/nginx@sha256:" + expectedDigest
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

			admissionReview.Request.Object.Raw = jsonEncode(createPod("harbor.localhost/rode-demo/nginx:latest"))

			expectedEvaluatePolicyResponse = &rode.EvaluatePolicyResponse{
				Pass: true,
			}
			expectedEvaluatePolicyError = nil

			expectedPolicyName = fake.LetterN(10)
			expectedPolicy = &rode.Policy{
				Id:   expectedPolicyId,
				Name: expectedPolicyName,
			}
			expectedGetPolicyError = nil
		})

		JustBeforeEach(func() {
			if mockRode.EvaluatePolicyStub == nil {
				mockRode.EvaluatePolicyReturns(expectedEvaluatePolicyResponse, expectedEvaluatePolicyError)
			}

			mockRode.GetPolicyReturns(expectedPolicy, expectedGetPolicyError)

			actualResponse, actualError = enforcer.Enforce(admissionReview)
		})

		It("should evaluate the policy in rode", func() {
			Expect(mockRode.EvaluatePolicyCallCount()).To(Equal(1))

			_, evaluatePolicyRequest, _ := mockRode.EvaluatePolicyArgsForCall(0)

			Expect(evaluatePolicyRequest.Policy).To(Equal(expectedPolicyId))
			Expect(evaluatePolicyRequest.ResourceUri).To(Equal(expectedResourceUri))
		})

		It("should allow the request", func() {
			Expect(actualResponse.Allowed).To(BeTrue())
			Expect(actualResponse.UID).To(Equal(expectedUid))
			Expect(actualError).To(BeNil())
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

		When("the image has a namespace in the default registry", func() {
			BeforeEach(func() {
				admissionReview.Request.Object.Raw = jsonEncode(createPod("foo/bar:latest"))
			})

			It("should not include the default registry in the resource uri", func() {
				Expect(mockRode.EvaluatePolicyCallCount()).To(Equal(1))
				_, actualRequest, _ := mockRode.EvaluatePolicyArgsForCall(0)

				Expect(actualRequest.ResourceUri).To(Equal("foo/bar@sha256:" + expectedDigest))
			})
		})

		When("the image does not have a namespace in the default registry", func() {
			BeforeEach(func() {
				admissionReview.Request.Object.Raw = jsonEncode(createPod("bar:latest"))
			})

			It("should not include the default registry or the default namespace in the resource uri", func() {
				Expect(mockRode.EvaluatePolicyCallCount()).To(Equal(1))
				_, actualRequest, _ := mockRode.EvaluatePolicyArgsForCall(0)

				Expect(actualRequest.ResourceUri).To(Equal("bar@sha256:" + expectedDigest))
			})
		})

		Describe("pod spec includes image secrets", func() {
			var (
				namespace           string
				pullSecret          *corev1.Secret
				expectedCredentials *registryCredentials
				actualAuth          authn.Authenticator
			)

			BeforeEach(func() {
				namespace = fake.Word()
				secretName := fake.Word()
				expectedCredentials = &registryCredentials{
					Username: fake.Username(),
					Password: fake.UUID(),
				}

				pullSecret = &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: namespace,
						Name:      secretName,
					},
					Data: map[string][]byte{
						".dockerconfigjson": jsonEncode(&imagePullSecret{
							Authentication: map[string]*registryCredentials{
								"https://harbor.localhost": expectedCredentials,
							},
						}),
					},
					Type: "kubernetes.io/dockerconfigjson",
				}

				pod := createPod("harbor.localhost/rode-demo/nginx:latest")
				pod.Namespace = namespace
				pod.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: secretName}}

				admissionReview.Request.Object.Raw = jsonEncode(pod)

				remoteWithAuth = func(auth authn.Authenticator) remote.Option {
					actualAuth = auth
					return remote.WithAuth(auth)
				}
			})

			AfterEach(func() {
				actualAuth = nil
			})

			When("the registry server matches an auth key in the pull secret", func() {
				BeforeEach(func() {
					Expect(mockK8sClient.Tracker().Add(pullSecret)).NotTo(HaveOccurred())
				})

				It("should add the credentials to the manifest request", func() {
					Expect(actualAuth).NotTo(BeNil())
					config, err := actualAuth.Authorization()

					Expect(err).NotTo(HaveOccurred())
					Expect(config).NotTo(BeNil())
					Expect(config.Username).To(Equal(expectedCredentials.Username))
					Expect(config.Password).To(Equal(expectedCredentials.Password))
				})

				It("should allow the request", func() {
					Expect(actualResponse.Allowed).To(BeTrue())
				})

				It("should not return an error", func() {
					Expect(actualError).To(BeNil())
				})
			})

			When("the image is from Docker Hub", func() {
				BeforeEach(func() {
					pod := createPod("nginx")
					pod.Namespace = namespace
					pod.Spec.ImagePullSecrets = []corev1.LocalObjectReference{{Name: pullSecret.Name}}
					admissionReview.Request.Object.Raw = jsonEncode(pod)

					pullSecret.Data = map[string][]byte{
						".dockerconfigjson": jsonEncode(&imagePullSecret{
							Authentication: map[string]*registryCredentials{
								"https://index.docker.io/v1/": expectedCredentials,
							},
						}),
					}

					Expect(mockK8sClient.Tracker().Add(pullSecret)).NotTo(HaveOccurred())
				})

				It("should add the credentials to the manifest request", func() {
					Expect(actualAuth).NotTo(BeNil())
					config, err := actualAuth.Authorization()

					Expect(err).NotTo(HaveOccurred())
					Expect(config).NotTo(BeNil())
					Expect(config.Username).To(Equal(expectedCredentials.Username))
					Expect(config.Password).To(Equal(expectedCredentials.Password))
				})
			})

			When("the registry server does not match the secret auth key", func() {
				BeforeEach(func() {
					pullSecret.Data = map[string][]byte{
						".dockerconfigjson": jsonEncode(&imagePullSecret{
							Authentication: map[string]*registryCredentials{
								"https://grc.io": expectedCredentials,
							},
						}),
					}

					Expect(mockK8sClient.Tracker().Add(pullSecret)).NotTo(HaveOccurred())
				})

				It("should not add credentials to the request", func() {
					Expect(actualAuth).To(BeNil())
				})
			})

			When("the pull secret is not found", func() {
				It("should deny the request", func() {
					Expect(actualResponse.Allowed).To(BeFalse())
					Expect(actualResponse.Result.Message).To(ContainSubstring("error fetching image pull secret"))
				})
			})

			When("the image pull secret is not the correct type", func() {
				BeforeEach(func() {
					pullSecret.Type = corev1.SecretType(fake.Word())
					Expect(mockK8sClient.Tracker().Add(pullSecret)).NotTo(HaveOccurred())
				})

				It("should deny the request", func() {
					Expect(actualResponse.Allowed).To(BeFalse())
					Expect(actualResponse.Result.Message).To(ContainSubstring("invalid secret type"))
				})
			})

			When("the image pull secret is missing the credential data key", func() {
				BeforeEach(func() {
					pullSecret.Data = map[string][]byte{}

					Expect(mockK8sClient.Tracker().Add(pullSecret)).NotTo(HaveOccurred())
				})

				It("should deny the request", func() {
					Expect(actualResponse.Allowed).To(BeFalse())
					Expect(actualResponse.Result.Message).To(ContainSubstring("missing key"))
				})
			})

			When("the secret JSON is unparseable", func() {
				BeforeEach(func() {
					pullSecret.Data = map[string][]byte{
						".dockerconfigjson": []byte("{"),
					}

					Expect(mockK8sClient.Tracker().Add(pullSecret)).NotTo(HaveOccurred())
				})

				It("should deny the request", func() {
					Expect(actualResponse.Allowed).To(BeFalse())
					Expect(actualResponse.Result.Message).To(ContainSubstring("error unmarshalling image pull secret"))
				})
			})

			When("the auth key does not contain a valid hostname", func() {
				BeforeEach(func() {
					pullSecret.Data = map[string][]byte{
						".dockerconfigjson": jsonEncode(&imagePullSecret{
							Authentication: map[string]*registryCredentials{
								"invalid": expectedCredentials,
							},
						}),
					}

					Expect(mockK8sClient.Tracker().Add(pullSecret)).NotTo(HaveOccurred())
				})

				It("should deny the request", func() {
					Expect(actualResponse.Allowed).To(BeFalse())
					Expect(actualResponse.Result.Message).To(ContainSubstring("error rewriting auth keys"))
				})
			})
		})

		When("the image name cannot be parsed", func() {
			BeforeEach(func() {
				admissionReview.Request.Object.Raw = jsonEncode(createPod("invalid@foo"))
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

			It("should not make any requests to rode", func() {
				Expect(mockRode.EvaluatePolicyCallCount()).To(BeZero())
				Expect(mockRode.GetPolicyCallCount()).To(BeZero())
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

			It("should not make any requests to rode", func() {
				Expect(mockRode.EvaluatePolicyCallCount()).To(BeZero())
				Expect(mockRode.GetPolicyCallCount()).To(BeZero())
			})
		})

		When("the container image fails policy", func() {
			BeforeEach(func() {
				expectedEvaluatePolicyResponse.Pass = false
			})

			It("should fetch the policy details from rode", func() {
				Expect(mockRode.GetPolicyCallCount()).To(Equal(1))
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
				expectedEvaluatePolicyResponse.Pass = false
				expectedGetPolicyError = errors.New("failed getting policy")
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

				pod := createPod("harbor.localhost/rode-demo/nginx:latest")
				pod.Spec.InitContainers = []corev1.Container{{Image: initContainerImage}}

				admissionReview.Request.Object.Raw = jsonEncode(pod)

				mockRode.EvaluatePolicyStub = func(ctx context.Context, request *rode.EvaluatePolicyRequest, option ...grpc.CallOption) (*rode.EvaluatePolicyResponse, error) {
					return &rode.EvaluatePolicyResponse{
						Pass: !strings.Contains(request.ResourceUri, initContainerImage),
					}, nil
				}
			})

			It("should deny the request", func() {
				Expect(actualResponse.Allowed).To(BeFalse())
				Expect(actualResponse.Result.Message).To(ContainSubstring(initContainerImage))
			})
		})

		When("an error occurs calling Rode", func() {
			BeforeEach(func() {
				expectedEvaluatePolicyError = errors.New("error evaluating policy")
			})

			It("should deny the response with a message", func() {
				Expect(actualResponse.Allowed).To(BeFalse())
				Expect(actualResponse.Result.Message).To(ContainSubstring(expectedEvaluatePolicyError.Error()))
			})

			It("should not return an error", func() {
				Expect(actualError).To(BeNil())
			})
		})

		When("the object is not a pod", func() {
			BeforeEach(func() {
				admissionReview.Request.Kind.Kind = fake.Word()
			})

			It("should allow the request", func() {
				Expect(actualResponse.Allowed).To(BeTrue())
			})

			It("should not return an error", func() {
				Expect(actualError).NotTo(HaveOccurred())
			})

			It("should not make any requests to rode", func() {
				Expect(mockRode.EvaluatePolicyCallCount()).To(BeZero())
				Expect(mockRode.GetPolicyCallCount()).To(BeZero())
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

func createPod(image string) *corev1.Pod {
	return &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Image: image,
				},
			},
		},
	}
}

func jsonEncode(val interface{}) []byte {
	data, err := json.Marshal(val)
	Expect(err).NotTo(HaveOccurred())

	return data
}
