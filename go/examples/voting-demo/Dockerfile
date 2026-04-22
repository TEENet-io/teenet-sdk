# syntax=docker/dockerfile:1

# Build stage
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

WORKDIR /src

# SDK root (replace target of examples/voting-demo/go.mod => ../../)
COPY go.mod go.sum ./
COPY client.go types.go ./
COPY internal/ ./internal/

# voting-demo sources
COPY examples/voting-demo/go.mod examples/voting-demo/go.sum ./examples/voting-demo/
COPY examples/voting-demo/main.go examples/voting-demo/types.go ./examples/voting-demo/
COPY examples/voting-demo/frontend/ ./examples/voting-demo/frontend/

WORKDIR /src/examples/voting-demo
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /out/voting-demo .

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /out/voting-demo /app/voting-demo
COPY --from=builder /src/examples/voting-demo/frontend /app/frontend

EXPOSE 8080
ENV PORT=8080

CMD ["/app/voting-demo"]
