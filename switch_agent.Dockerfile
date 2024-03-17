FROM golang:1.22.0-bookworm

RUN apt-get update && \
    echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y tshark

RUN apt install -y build-essential
RUN apt install -y pkg-config
RUN apt install -y clang
RUN apt install -y llvm
RUN apt install -y m4
RUN apt install -y git
RUN apt install -y libelf-dev
RUN apt install -y libpcap-dev
RUN apt install -y iproute2
RUN apt install -y iputils-ping
RUN apt install -y linux-headers-generic
RUN apt install -y libbpf-dev
RUN apt install -y linux-libc-dev
RUN apt install -y cmake
RUN apt install -y libpcap-dev
RUN apt install -y libcap-ng-dev
RUN apt install -y libbfd-dev
RUN ln -sf /usr/include/asm-generic/ /usr/include/asm
RUN apt install -y libcap-dev
RUN echo 'alias ll="ls -al"' >> ~/.bashrc

RUN mkdir /tools/

WORKDIR /tools/

RUN git clone --recurse-submodules https://github.com/libbpf/bpftool.git

RUN make -C bpftool/src/ install

RUN git clone --recurse-submodules https://github.com/xdp-project/xdp-tools.git

RUN make -C xdp-tools/ install

RUN mkdir /switch-source/

COPY go.mod /switch-source
COPY go.sum /switch-source
COPY ./ebpf/ /switch-source/ebpf/
COPY ./cmd/switch_agent/ /switch-source/cmd/switch_agent/

WORKDIR /switch-source/

#RUN go install github.com/go-delve/delve/cmd/dlv@latest
RUN go mod download
RUN go generate ./ebpf/switch_agent/

RUN go build -o /switch-build/switch_agent ./cmd/switch_agent/main.go
# for debuging comment above and uncomment below 2 commands & comment above
#RUN go build -gcflags="all=-N -l" -o /switch-build/switch_agent ./cmd/switch_agent/main.go
#EXPOSE 40000



#ENTRYPOINT ["dlv", "--listen=:40000", "--headless=true", "--api-version=2", "--accept-multiclient", "exec", "/switch-build/switch_agent", "--", "--if-name", "eth1"]

ENTRYPOINT ["sh", "-c", "trap 'exit 0' SIGTERM SIGINT; while true; do echo 'Container is running...'; sleep 10; done"]

#ENTRYPOINT ["/switch-build/switch_agent", "--if-name", "eth1"]