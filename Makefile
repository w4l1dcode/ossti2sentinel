all: run

run:
	go run ./cmd/... -config=dev.yml

build:
	CGO_ENABLED=0 go build -o vm2sentinel ./cmd/...

test:
	go test -v ./...

clean:
	rm -r dist/ OpenSourceThreatIntelIngestion || true

update:
	go get -u ./...
	go mod tidy
