ARG TERM=xterm
FROM debian:buster-slim

# get dependency
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    pkg-config \
    autoconf \
    make \
    cmake \ 
    libssl-dev \
    protobuf-compiler \
    ninja-build \
    clang

# Install rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o rustup_install.sh && chmod +x rustup_install.sh && ./rustup_install.sh -y && rm rustup_install.sh
RUN bash -c "/root/.cargo/bin/rustup update && /root/.cargo/bin/rustup target add x86_64-unknown-linux-gnu"

CMD ["/bin/bash"]