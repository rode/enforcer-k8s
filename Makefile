MAKEFLAGS += --silent

.PHONY: deploy

deploy:
	docker build -t ghcr.io/rode/enforcer-k8s .
	helm template enforcer-k8s | kubectl delete -f - --ignore-not-found
	helm template enforcer-k8s | kubectl apply -f -
