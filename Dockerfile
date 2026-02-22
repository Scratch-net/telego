# Build stage
FROM golang:latest AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -tags="poll_opt,gc_opt" -ldflags="-s -w" -o telego ./cmd/telego

# Final stage
FROM scratch

COPY --from=builder /src/telego /telego

ENTRYPOINT ["/telego"]
CMD ["run", "-c", "/config.toml"]
