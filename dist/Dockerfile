FROM alpine:latest AS certificates

FROM scratch

ARG TARGETPLATFORM
COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY ${TARGETPLATFORM}/telego /telego

ENTRYPOINT ["/telego"]
CMD ["run", "-c", "/config.toml"]
