# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS builder

WORKDIR /src
RUN apk add --no-cache ca-certificates git

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN cd /src/examples && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/passkey-web-demo ./passkey-web-demo

FROM alpine:3.22

RUN apk add --no-cache ca-certificates && \
    addgroup -S app && adduser -S -G app app

WORKDIR /app
COPY --from=builder /out/passkey-web-demo /app/passkey-web-demo
COPY --from=builder /src/examples/passkey-web-demo/frontend /app/frontend

ENV DEMO_HOST=0.0.0.0 \
    DEMO_PORT=18090 \
    DEMO_FRONTEND_DIR=/app/frontend

EXPOSE 18090
USER app
ENTRYPOINT ["/app/passkey-web-demo"]
