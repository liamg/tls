default: test

test:
	go test -race -v ./...

.PHONY: default test