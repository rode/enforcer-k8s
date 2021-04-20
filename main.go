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

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rode/enforcer-k8s/config"
	"github.com/rode/enforcer-k8s/enforcer"
	"k8s.io/client-go/tools/clientcmd"

	"google.golang.org/grpc"

	"go.uber.org/zap"

	rode "github.com/rode/rode/proto/v1alpha1"
	"k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	log        *zap.Logger
	client     *kubernetes.Clientset
	rodeClient rode.RodeClient
)

func webhook(k8sEnforcer *enforcer.Enforcer) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Info("request received")
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Error("Error reading response body", zap.Error(err))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if contentType := r.Header.Get("Content-Type"); contentType != "application/json" {
			log.Error("Unexpected content type", zap.String("contentType", contentType))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		admissionReview := &v1.AdmissionReview{}
		if err := json.Unmarshal(body, admissionReview); err != nil {
			log.Error("Unable to deserialize request body: %s", zap.Error(err))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		response, err := k8sEnforcer.Enforce(admissionReview)
		if err != nil {
			log.Error("error building admission response", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		admissionReview.Response = response

		log.Info("raw response", zap.Any("response", admissionReview.Response))
		responseBytes, err := json.Marshal(admissionReview)
		if err != nil {
			log.Error("error serializing response", zap.Error(err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(responseBytes); err != nil {
			log.Error("error writing response", zap.Error(err))
			return
		}

		log.Info("successful request")
	}
}

func healthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func newK8sClient(kubernetesConfig *config.KubernetesConfig) *kubernetes.Clientset {
	var (
		clusterConfig *rest.Config
		err           error
	)

	if kubernetesConfig.InCluster {
		clusterConfig, err = rest.InClusterConfig()
		if err != nil {
			log.Fatal("Failed to get cluster config", zap.Error(err))
		}
	} else {
		clusterConfig, err = clientcmd.BuildConfigFromFlags("", kubernetesConfig.ConfigFile)
	}

	client, err := kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		log.Fatal("Error creating kubernetes client", zap.Error(err))
	}

	return client
}

func main() {
	log, _ = zap.NewDevelopment()

	conf, err := config.Build(os.Args[0], os.Args[1:])
	if err != nil {
		log.Fatal("failed to build config", zap.Error(err))
	}

	client = newK8sClient(conf.Kubernetes)

	secret, err := client.CoreV1().Secrets(conf.Tls.Namespace).Get(context.Background(), conf.Tls.Name, metav1.GetOptions{})
	if err != nil {
		log.Fatal("Failed to find secret", zap.Error(err), zap.String("secret", conf.Tls.Secret))
	}
	certData, ok := secret.Data["tls.crt"]
	if !ok {
		log.Fatal("secret missing tls.crt", zap.String("secret", conf.Tls.Secret))
	}

	keyData, ok := secret.Data["tls.key"]
	if !ok {
		log.Fatal("secret missing tls.key", zap.String("secret", conf.Tls.Secret))
	}

	certFile, err := ioutil.TempFile(os.TempDir(), "cert-")
	if err != nil {
		log.Fatal("error creating temp file for cert", zap.Error(err))
	}

	keyFile, err := ioutil.TempFile(os.TempDir(), "key-")
	if err != nil {
		log.Fatal("error creating temp file for key", zap.Error(err))
	}

	defer os.Remove(certFile.Name())
	defer os.Remove(keyFile.Name())

	if _, err := certFile.Write(certData); err != nil {
		log.Fatal("error writing cert file", zap.Error(err))
	}

	if err := certFile.Close(); err != nil {
		log.Fatal("error closing cert file", zap.Error(err))
	}

	if _, err := keyFile.Write(keyData); err != nil {
		log.Fatal("error writing key file", zap.Error(err))
	}

	if err := keyFile.Close(); err != nil {
		log.Fatal("error closing key file", zap.Error(err))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	conn, err := grpc.DialContext(ctx, conf.RodeHost, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatal("failed to establish grpc connection to Rode", zap.Error(err))
	}
	defer conn.Close()

	rodeClient = rode.NewRodeClient(conn)

	k8sEnforcer := enforcer.NewEnforcer(
		log.Named("Enforcer"),
		conf,
		rodeClient,
	)

	http.HandleFunc("/", webhook(k8sEnforcer))
	http.HandleFunc("/healthz", healthz)

	server := &http.Server{
		Addr: fmt.Sprintf(":%d", conf.Port),
	}

	go func() {
		if err := server.ListenAndServeTLS(certFile.Name(), keyFile.Name()); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal("error starting server", zap.Error(err))
		}
	}()

	log.Info("listening", zap.Int("port", conf.Port))

	s := make(chan os.Signal, 1)
	signal.Notify(s, syscall.SIGINT, syscall.SIGTERM)

	<-s

	log.Info("Shutting down...")
	server.Shutdown(context.Background())
}
