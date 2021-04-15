package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"k8s.io/api/admission/v1"
	"k8s.io/klog"
)

func webhook(w http.ResponseWriter, r *http.Request) {
	klog.Info("request received")

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		klog.Errorf("Error reading response body: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if contentType := r.Header.Get("Content-Type"); contentType != "application/json" {
		klog.Errorf("Unexpected content type: %s", contentType)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	admissionReview := &v1.AdmissionReview{}
	if err := json.Unmarshal(body, admissionReview); err != nil {
		klog.Errorf("Unable to deserialize request body: %s", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	admissionReview.Response = &v1.AdmissionResponse{
		UID:     admissionReview.Request.UID,
		Allowed: true,
	}

	klog.Infof("raw response: %v", admissionReview.Response)
	responseBytes, err := json.Marshal(admissionReview)
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
	port := 8001
	http.HandleFunc("/", webhook)
	http.HandleFunc("/healthz", healthz)

	klog.Infof("listening on %d", port)
	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", port),
		TLSConfig: loadTlsConfig(),
	}

	if err := server.ListenAndServeTLS("", ""); err != nil {
		klog.Fatalf("error starting server: %s", err)
	}
}
