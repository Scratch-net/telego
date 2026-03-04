FROM scratch

ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/telego /telego

ENTRYPOINT ["/telego"]
CMD ["run", "-c", "/config.toml"]
