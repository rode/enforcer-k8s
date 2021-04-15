package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/klog"
)

var scheme = runtime.NewScheme()
var codecs = serializer.NewCodecFactory(scheme)

const (
	admissionReviewKind = "AdmissionReview"
)

func vaw(w http.ResponseWriter, r *http.Request) {
	klog.Info("request received")

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		klog.Errorf("Error reading response body: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	deserializer := codecs.UniversalDeserializer()
	object, gvk, err := deserializer.Decode(body, nil, nil)
	if err != nil {
		klog.Errorf("Error decoding body: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var responseObj runtime.Object
	switch *gvk {
	case v1.SchemeGroupVersion.WithKind(admissionReviewKind):
		requested, ok := object.(*v1.AdmissionReview)
		if !ok {
			klog.Errorf("Expected v1.AdmissionReview, got: %T", object)
			return
		}
		response := &v1.AdmissionReview{}
		response.SetGroupVersionKind(*gvk)
		response.Response = &v1.AdmissionResponse{}
		response.Response.UID = requested.Request.UID
		response.Response.Allowed = true

		responseObj = response
	default:
		msg := fmt.Sprintf("Unsupported group kind version: %v", gvk)
		klog.Errorf(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return
	}

	klog.Infof("raw response: %v", responseObj)
	responseBytes, err := json.Marshal(responseObj)
	if err != nil {
		klog.Errorf("error serializing response: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(responseBytes); err != nil {
		klog.Errorf("error writing response: %s", err)
		return
	}

	klog.Info("successful request")
}

func healthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func populateSchema() {
	utilruntime.Must(v1.AddToScheme(scheme))
	//utilruntime.Must(corev1.AddToScheme(scheme))
}

func getEnv(envName string) string {
	value, present := os.LookupEnv(envName)
	if !present {
		klog.Fatalf("Expected %s to be set", envName)
	}

	return value
}

func loadTlsConfig() *tls.Config {
	c, err := tls.LoadX509KeyPair(getEnv("TLS_CLIENT_CERT"), getEnv("TLS_CLIENT_KEY"))
	if err != nil {
		klog.Fatalf("error loading cert: %s", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{c},
	}
}

func main() {
	populateSchema()
	port := 8001

	http.HandleFunc("/", vaw)
	http.HandleFunc("/healthz", healthz)

	klog.Infof("listening on %d", port)
	server := &http.Server{
		Addr: fmt.Sprintf(":%d", port),
		TLSConfig: loadTlsConfig(),
	}

	if err := server.ListenAndServeTLS("", ""); err != nil {
		klog.Fatalf("error starting server: %s", err)
	}
}
