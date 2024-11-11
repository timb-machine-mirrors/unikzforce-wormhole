FROM ubuntu:24.04

RUN apt-get update && \
    echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y tshark

RUN apt install -y golang-go
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
RUN apt install -y dwarves
RUN apt install -y locales
RUN apt install -y bash-completion
RUN apt install -y cargo
RUN locale-gen en_US.UTF-8
RUN update-locale LANG=en_US.UTF-8
RUN echo 'alias ll="ls -al"' >> ~/.bashrc
RUN echo 'if [ -f /etc/bash_completion ]; then . /etc/bash_completion; fi' >> ~/.bashrc
RUN mkdir -p ~/.local/share/bash-completion/completions
RUN echo 'docker completion bash > ~/.local/share/bash-completion/completions/docker' >> ~/.bashrc
RUN git clone --depth 1 https://github.com/junegunn/fzf.git ~/.fzf
RUN ~/.fzf/install --all

RUN cargo install --locked zellij

RUN echo 'PATH=$PATH:$HOME/.cargo/bin' >> ~/.bashrc

RUN mkdir /tools/

WORKDIR /tools/

RUN git clone --recurse-submodules https://github.com/libbpf/bpftool.git

RUN make -C bpftool/src/ install

RUN git clone --recurse-submodules https://github.com/xdp-project/xdp-tools.git

RUN make -C xdp-tools/ install

WORKDIR /

ENV GOPATH=/go
ENV PATH=$PATH:$GOPATH/bin
RUN mkdir -p $GOPATH/bin


RUN apt install -y protobuf-compiler
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# install CLAB
# containelab version will be set in devcontainer.json
ARG _CLAB_VERSION

# Set permissions for mounts in devcontainer.json
#RUN mkdir -p /home/vscode/.vscode-server/bin
#RUN chown -R vscode:vscode /home/vscode/.vscode-server

# install some basic tools inside the container
# adjust this list based on your demands
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    sshpass \
    curl \
    iputils-ping \
    htop \
    yamllint \
    && rm -rf /var/lib/apt/lists/* \
    && rm -Rf /usr/share/doc && rm -Rf /usr/share/man \
    && apt-get clean

# install preferred version of the containerlab
RUN bash -c "$(curl -sL https://get.containerlab.dev)" -- -v ${_CLAB_VERSION}
