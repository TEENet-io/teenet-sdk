# Build stage
FROM golang:1.24-alpine AS builder

# Install necessary build tools
RUN apk add --no-cache git

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY *.go ./
COPY frontend/ ./frontend/

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o voting-demo .

# Runtime stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/voting-demo .

# Copy frontend files
COPY --from=builder /app/frontend ./frontend

# Expose default port
EXPOSE 8080

# Set environment variables (can be overridden at runtime)
ENV PORT=8080

# Run the application
CMD ["./voting-demo"]
