FROM fedora:41

ARG GO_VERSION=1.24.2

RUN dnf install -y wget tar

RUN wget "https://go.dev/dl/go${GO_VERSION}.linux-$(arch | sed s/aarch64/arm64/ | sed s/x86_64/amd64/).tar.gz"
RUN rm -rf /usr/local/go && tar -C /usr/local -xzf go${GO_VERSION}.linux-$(arch | sed s/aarch64/arm64/ | sed s/x86_64/amd64/).tar.gz
RUN mkdir -p /root/go

ENV PATH="$PATH:/usr/local/go/bin:/root/go/bin"
ENV GOPATH=/root/go

RUN mkdir -p /root/auth
WORKDIR /root/auth
COPY go.mod .
COPY go.sum .
RUN go mod download