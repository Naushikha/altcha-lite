# Stage 1: Build
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum first to leverage caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .
RUN go build -o altcha-lite .

# Stage 2: Minimal runtime image
FROM alpine:latest

RUN adduser -D altcha
WORKDIR /home/altcha

COPY --from=builder /app/altcha-lite .
USER altcha

CMD ["./altcha-lite"]
