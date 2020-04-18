default: test

test:
	go test -mod=vendor -race -v ./...

.PHONY: default test