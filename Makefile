REGISTRY=registry.hub.docker.com
IMAGE=dvitali/treafik-dex-auth
VERSION=$(shell git describe --tags --always --dirty)

version:
	@echo "$(VERSION)"

docker-build:
	docker build -t "$(REGISTRY)/$(IMAGE):$(VERSION)" .
	docker tag "$(REGISTRY)/$(IMAGE):$(VERSION)" "$(REGISTRY)/$(IMAGE):latest" .

docker-push:
	docker push "$(REGISTRY)/$(IMAGE):$(VERSION)"
	docker push "$(REGISTRY)/$(IMAGE):latest"