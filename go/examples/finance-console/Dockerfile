# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS builder

WORKDIR /src
RUN apk add --no-cache ca-certificates git

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN cd /src/examples && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/finance-console ./finance-console

FROM alpine:3.22

RUN apk add --no-cache ca-certificates && \
    addgroup -S app && adduser -S -G app app

WORKDIR /app
COPY --from=builder /out/finance-console /app/finance-console
COPY --from=builder /src/examples/finance-console/frontend /app/frontend

ENV DEMO_HOST=0.0.0.0 \
    DEMO_PORT=18091 \
    DEMO_FRONTEND_DIR=/app/frontend

EXPOSE 18091
USER app
ENTRYPOINT ["/app/finance-console"]
