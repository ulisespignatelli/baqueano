# syntax=docker/dockerfile:1
# Imagen mínima: binario estático sobre distroless, sin shell, usuario sin privilegios.
FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
COPY api/ /src/api/
RUN npm run build

FROM golang:1.22-alpine AS go
WORKDIR /src/backend
COPY backend/go.mod ./
RUN go mod download
COPY backend/ ./
COPY --from=web /src/backend/internal/adapters/httpapi/ui/dist ./internal/adapters/httpapi/ui/dist
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/baqueano ./cmd/baqueano && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=go /out/baqueano /baqueano
COPY --from=go --chown=65532:65532 /out/data /data
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/baqueano"]
# Dentro del contenedor hay que escuchar en 0.0.0.0, y eso exige un token (BAQUEANO_TOKEN).
CMD ["serve", "--addr", "0.0.0.0:8080", "--data", "/data"]
