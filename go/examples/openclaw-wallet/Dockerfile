FROM golang:1.24-alpine AS builder

RUN apk add --no-cache gcc musl-dev sqlite-dev

# ── Build context is teenet-sdk/go/ (pack.sh passes ../.. as context) ──
# Step 1: place the full SDK at /sdk so the replace directive can point to it.
WORKDIR /sdk
COPY . .

# Step 2: set up the wallet build directory with its own go.mod.
WORKDIR /build
COPY examples/openclaw-wallet/go.mod examples/openclaw-wallet/go.sum ./
RUN sed -i 's|replace github.com/TEENet-io/teenet-sdk/go => ../..|replace github.com/TEENet-io/teenet-sdk/go => /sdk|' go.mod
RUN go mod download

# Step 3: copy wallet source and build.
# COPY restores the original go.mod (with ../.. path), so re-apply the fix before building.
COPY examples/openclaw-wallet/ .
RUN sed -i 's|replace github.com/TEENet-io/teenet-sdk/go => ../..|replace github.com/TEENet-io/teenet-sdk/go => /sdk|' go.mod \
    && CGO_ENABLED=1 GOOS=linux go build -o wallet-app .

# ─── Runtime image ────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache sqlite-libs ca-certificates tzdata

WORKDIR /app

COPY --from=builder /build/wallet-app .
COPY --from=builder /build/frontend ./frontend
COPY --from=builder /build/chains.json .

RUN mkdir -p /data

EXPOSE 8080

ENV HOST=0.0.0.0 \
    PORT=8080 \
    DATA_DIR=/data \
    CONSENSUS_URL=http://localhost:8089

ENTRYPOINT ["./wallet-app"]
