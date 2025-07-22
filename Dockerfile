# Build stage
FROM golang:1.21.14-alpine3.19 AS builder

# Install git and ca-certificates
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main cmd/server/main.go

# Final stage
FROM alpine:3.19.0

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1001 -S appuser && adduser -u 1001 -S appuser -G appuser

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/main .

# Copy environment file template
COPY --from=builder /app/.env.example .env.example

# Change ownership to non-root user
RUN chown -R appuser:appuser /root/
USER appuser

# Expose port
EXPOSE 8080

# Run the application
CMD ["./main"]