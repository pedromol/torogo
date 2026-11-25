FROM golang:alpine AS builder

WORKDIR /app

COPY go.mod ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix static -ldflags "-s -w" -o torclient ./cmd/torogo

FROM gcr.io/distroless/static-debian12 AS runtime

COPY --from=builder /app/torclient /torclient

ENTRYPOINT ["/torclient"]