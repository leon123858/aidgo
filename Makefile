all:
	echo "Do nothing"

test:
	go test -v ./...

deploy:
	git ls-remote --tags origin
	git tag v0.1.15
	git push origin v0.1.15
	git tag lastest -f
	git push origin lastest -f