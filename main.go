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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rode/enforcer-k8s/config"
	"github.com/rode/enforcer-k8s/enforcer"
	"google.golang.org/grpc/credentials"
	"k8s.io/client-go/tools/clientcmd"

	"google.golang.org/grpc"

	"go.uber.org/zap"

	rode "github.com/rode/rode/proto/v1alpha1"
	"k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func webhook(logger *zap.Logger, k8sEnforcer *enforcer.Enforcer) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		logger.Info("request received")
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			logger.Error("Error reading response body", zap.Error(err))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if contentType := r.Header.Get("Content-Type"); contentType != "application/json" {
			logger.Error("Unexpected content type", zap.String("contentType", contentType))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		admissionReview := &v1.AdmissionReview{}
		if err := json.Unmarshal(body, admissionReview); err != nil {
			logger.Error("Unable to deserialize request body: %s", zap.Error(err))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		response, err := k8sEnforcer.Enforce(admissionReview)
		if err != nil {
			logger.Error("error building admission response", zap.Error(err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		admissionReview.Response = response

		logger.Info("raw response", zap.Any("response", admissionReview.Response))
		responseBytes, err := json.Marshal(admissionReview)
		if err != nil {
			logger.Error("error serializing response", zap.Error(err))
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write(responseBytes); err != nil {
			logger.Error("error writing response", zap.Error(err))
			return
		}

		logger.Info("successful request")
	}
}

func healthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func newK8sClient(logger *zap.Logger, kubernetesConfig *config.KubernetesConfig) *kubernetes.Clientset {
	var (
		clusterConfig *rest.Config
		err           error
	)

	if kubernetesConfig.InCluster {
		clusterConfig, err = rest.InClusterConfig()
		if err != nil {
			logger.Fatal("Failed to get cluster config", zap.Error(err))
		}
	} else {
		clusterConfig, err = clientcmd.BuildConfigFromFlags("", kubernetesConfig.ConfigFile)
	}

	client, err := kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		logger.Fatal("Error creating kubernetes client", zap.Error(err))
	}

	return client
}

func newRodeClient(logger *zap.Logger, conf *config.Config) (*grpc.ClientConn, rode.RodeClient) {
	dialOptions := []grpc.DialOption{
		grpc.WithBlock(),
	}
	if conf.Rode.Insecure {
		dialOptions = append(dialOptions, grpc.WithInsecure())
	} else {
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	conn, err := grpc.DialContext(ctx, conf.Rode.Host, dialOptions...)
	if err != nil {
		logger.Fatal("failed to establish grpc connection to Rode", zap.Error(err))
	}

	return conn, rode.NewRodeClient(conn)
}

func createTlsConfig(logger *zap.Logger, conf *config.Config, client *kubernetes.Clientset) *tls.Config {
	secret, err := client.CoreV1().Secrets(conf.Tls.Namespace).Get(context.Background(), conf.Tls.Name, metav1.GetOptions{})
	if err != nil {
		logger.Fatal("Failed to find secret", zap.Error(err), zap.String("secret", conf.Tls.Secret))
	}

	cert, ok := secret.Data["tls.crt"]
	if !ok {
		logger.Fatal("Secret missing tls.crt", zap.String("secret", conf.Tls.Secret))
	}

	key, ok := secret.Data["tls.key"]
	if !ok {
		logger.Fatal("Secret missing tls.key", zap.String("secret", conf.Tls.Secret))
	}

	certificate, err := tls.X509KeyPair(cert, key)
	if err != nil {
		logger.Fatal("Error loading key pair", zap.Error(err))
	}

	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
	}
}

func createLogger(debug bool) (*zap.Logger, error) {
	if debug {
		return zap.NewDevelopment()
	}

	return zap.NewProduction()
}

func main() {
	conf, err := config.Build(os.Args[0], os.Args[1:])
	if err != nil {
		log.Fatalf("failed to build config: %s", err)
	}

	logger, err := createLogger(conf.Debug)
	if err != nil {
		log.Fatalf("failed to create logger:: %s", err)
	}

	client := newK8sClient(logger, conf.Kubernetes)

	conn, rodeClient := newRodeClient(logger, conf)
	defer conn.Close()

	k8sEnforcer := enforcer.NewEnforcer(
		logger.Named("Enforcer"),
		conf,
		client,
		rodeClient,
	)

	http.HandleFunc("/", webhook(logger, k8sEnforcer))
	http.HandleFunc("/healthz", healthz)

	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", conf.Port),
		TLSConfig: createTlsConfig(logger, conf, client),
	}

	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal("error starting server", zap.Error(err))
		}
	}()

	logger.Info("listening", zap.Int("port", conf.Port))

	s := make(chan os.Signal, 1)
	signal.Notify(s, syscall.SIGINT, syscall.SIGTERM)

	<-s

	logger.Info("Shutting down...")
	server.Shutdown(context.Background())
}
