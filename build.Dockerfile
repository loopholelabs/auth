FROM fedora:42

ARG GO_VERSION=1.24.2
ARG BUN_VERSION=1.2.23

RUN dnf install -y curl wget tar unzip

RUN wget "https://go.dev/dl/go${GO_VERSION}.linux-$(arch | sed s/aarch64/arm64/ | sed s/x86_64/amd64/).tar.gz"
RUN rm -rf /usr/local/go && tar -C /usr/local -xzf go${GO_VERSION}.linux-$(arch | sed s/aarch64/arm64/ | sed s/x86_64/amd64/).tar.gz
RUN mkdir -p /root/go

ENV GOPATH=/root/go
ENV PATH="$PATH:/usr/local/go/bin:/root/go/bin"

RUN curl -fsSL https://bun.com/install | bash -s "bun-v${BUN_VERSION}"

ENV BUN_INSTALL="/root/.bun"
ENV PATH="$PATH:$BUN_INSTALL/bin"

RUN mkdir -p /root/auth
WORKDIR /root/auth
COPY go.mod .
COPY go.sum .
RUN go mod download

RUN mkdir -p frontend
COPY frontend/package.json frontend/package.json
COPY frontend/bun.lock frontend/bun.lock
WORKDIR /root/auth/frontend
RUN bun install

WORKDIR /root/auth