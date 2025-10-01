FROM cgr.dev/chainguard/wolfi-base:latest

RUN mkdir -p /etc/auth/frontend

COPY build/auth /usr/bin/auth
COPY build/frontend /etc/auth/frontend

ENV AUTH_FRONTEND=/etc/auth/frontend

USER 65534:65534
ENTRYPOINT ["/usr/bin/auth"]