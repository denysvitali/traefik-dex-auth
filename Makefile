REGISTRY=docker.io
IMAGE=dvitali/traefik-dex-auth
VERSION=$(shell git describe --tags --always --dirty)

version:
	@echo "$(VERSION)"

test:
	go test ./...

docker-build:
	docker build -t "$(REGISTRY)/$(IMAGE):$(VERSION)" .
	docker tag "$(REGISTRY)/$(IMAGE):$(VERSION)" "$(REGISTRY)/$(IMAGE):latest"

docker-push:
	docker push "$(REGISTRY)/$(IMAGE):$(VERSION)"
	docker push "$(REGISTRY)/$(IMAGE):latest"