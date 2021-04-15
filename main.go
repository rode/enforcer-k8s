package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/heroku/docker-registry-client/registry"

	rode "github.com/rode/rode/proto/v1alpha1"
	"k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	log      *zap.Logger
	client   *kubernetes.Clientset
	conf *config
	rodeClient rode.RodeClient
)

type config struct {
	policyId string
	tlsSecretName string
	port int
	rodeHost string
}

func enforce(review *v1.AdmissionReview) (*v1.AdmissionResponse, error) {
	response := &v1.AdmissionResponse{
		UID:     review.Request.UID,
		Allowed: true,
	}

	objectKind := review.Request.Kind.Kind
	if objectKind != "Pod" {
		return response, nil
	}

	var pod corev1.Pod
	if err := json.Unmarshal(review.Request.Object.Raw, &pod); err != nil {
		log.Error("error unmarshalling pod", zap.Error(err))
		response.Allowed = false
		return response, nil
	}

	for _, container := range pod.Spec.Containers {
		// find container status
		var status corev1.ContainerStatus
		for _, s := range pod.Status.ContainerStatuses {
			if s.Name == container.Name {
				status = s
			}
		}
		if status.Name == "" {
			log.Error("could not find container status", zap.Any("container", container))
			response.Allowed = false
			return response, nil
		}

		

		hub, err := registry.New("http://harbor.localhost", "", "")

		manifest, err := hub.ManifestV2("rode-demo/alpine", "latest")


		imageId := strings.TrimPrefix(status.ImageID, "docker-pullable://")
		log.Debug("evaluating policy against image", zap.String("image", imageId))

		res, err := rodeClient.EvaluatePolicy(context.Background(), &rode.EvaluatePolicyRequest{
			Policy: conf.policyId,
			ResourceUri: imageId,
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

func webhook(w http.ResponseWriter, r *http.Request) {
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

	response, err := enforce(admissionReview)
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

func healthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func newK8sClient() *kubernetes.Clientset {
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal("Failed to get cluster config", zap.Error(err))
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatal("Error creating kubernetes client", zap.Error(err))
	}

	return client
}

func getCurrentNamespace() (string, error) {
	b, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(b)), nil
}

func main() {
	log, _ = zap.NewDevelopment()

	conf = &config{}

	flag.StringVar(&conf.policyId, "policy-id", "", "The ID of the policy that the resource uri is evaluated against.")
	flag.StringVar(&conf.tlsSecretName, "tls-secret", "", "Secret name that holds the webhook TLS configuration")
	flag.StringVar(&conf.rodeHost, "rode-host", "", "Rode host")
	flag.IntVar(&conf.port, "port", 8001, "The port to bind")
	flag.Parse()

	if conf.policyId == "" {
		log.Fatal("must set policy id")
	}

	namespace, err := getCurrentNamespace()
	if err != nil {
		log.Fatal("Error retrieving namespace", zap.Error(err))
	}

	client = newK8sClient()

	secret, err := client.CoreV1().Secrets(namespace).Get(context.Background(), conf.tlsSecretName, metav1.GetOptions{})
	if err != nil {
		log.Fatal("Failed to find secret", zap.Error(err))
	}
	certData, ok := secret.Data["tls.crt"]
	if !ok {
		log.Fatal("secret missing tls.crt", zap.String("secret", conf.tlsSecretName))
	}

	keyData, ok := secret.Data["tls.key"]
	if !ok {
		log.Fatal("secret missing tls.key", zap.String("secret", conf.tlsSecretName))
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
	conn, err := grpc.DialContext(ctx, conf.rodeHost, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatal("failed to establish grpc connection to Rode", zap.Error(err))
	}
	defer conn.Close()

	rodeClient = rode.NewRodeClient(conn)

	http.HandleFunc("/", webhook)
	http.HandleFunc("/healthz", healthz)

	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", conf.port),
	}

	go func(){
		if err := server.ListenAndServeTLS(certFile.Name(), keyFile.Name()); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal("error starting server", zap.Error(err))
		}
	}()

	log.Info("listening", zap.Int("port", conf.port))

	s := make(chan os.Signal, 1)
	signal.Notify(s, syscall.SIGINT, syscall.SIGTERM)

	<-s

	log.Info("Shutting down...")
	server.Shutdown(context.Background())
}
