NEXT_VERSION := $(shell ./get_next_version.sh)

all:
	go test -v ./...

deploy:
	$(eval NEXT_VERSION := $(bash ./scripts/deploy.sh))
	@echo "Bumping version to $(NEXT_VERSION)"
	@git tag $(NEXT_VERSION)
	@git push origin $(NEXT_VERSION)