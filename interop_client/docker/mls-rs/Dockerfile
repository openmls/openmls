FROM rust:latest

RUN apt-get -y update && apt-get -y install protobuf-compiler git

ENV HOME=/home/user

RUN useradd -m user
USER user
WORKDIR ${HOME}

RUN git clone --recursive https://github.com/awslabs/mls-rs.git ${HOME}/mls-rs
WORKDIR ${HOME}/mls-rs
# Pin to a known-good main commit for reproducible builds (main as of 2026-07-18).
RUN git checkout 42131c9959efb1d3928428259bc89853027f730d
WORKDIR ${HOME}/mls-rs/test_harness_integration

# Build the interop client with all default features
RUN cargo build --release -p harness_client

EXPOSE 50053

ENTRYPOINT [ "/home/user/mls-rs/target/release/harness_client" ]
CMD [ "-p", "50053" ]
