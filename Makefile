NEXT_VERSION := $(shell ./get_next_version.sh)

all:
	go test -v ./...

deploy:
	git ls-remote --tags origin
	git tag v0.1.1
	git push origin v0.1.1
	git tag lastest -f
	git push origin lastest -f