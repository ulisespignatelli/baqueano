VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: docker build build-go web web-demo demo-data test test-go test-web lint api-types serve clean bench

build: web build-go ## Panel + binario con el panel embebido

build-go:
	cd backend && CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o ../bin/baqueano ./cmd/baqueano

web:
	cd web && npm ci && npm run build

web-demo: ## Demo estática para GitHub Pages (web/dist)
	cd web && npm ci && npm run build:demo

demo-data: build-go ## Regenera los datos ficticios de la demo
	rm -rf /tmp/baqueano-demo web/demo-public/demo
	./bin/baqueano demo --data /tmp/baqueano-demo --out web/demo-public/demo

test: test-go test-web

test-go:
	cd backend && go test -race -count=1 ./...

test-web:
	cd web && npm ci && npm run typecheck && npm test

lint:
	cd backend && test -z "$$(gofmt -l .)" && go vet ./...

bench: build-go ## Benchmark de precisión del motor (escribe docs/benchmark.md)
	cd backend && ../bin/baqueano bench --corpus ../bench --out ../docs/benchmark.md

api-types:
	cd web && npm run gen:api

serve: build
	./bin/baqueano serve

clean:
	rm -rf bin web/dist backend/internal/adapters/httpapi/ui/dist

docker: ## Imagen local
	docker build --build-arg VERSION=$(VERSION) -t baqueano:$(VERSION) .
