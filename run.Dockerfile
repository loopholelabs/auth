FROM cgr.dev/chainguard/wolfi-base:latest
COPY build/auth /usr/bin/auth
USER 65534:65534
ENTRYPOINT ["/usr/bin/auth"]