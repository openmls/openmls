
FROM ubuntu:20.04 as builder

## Install build dependencies.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y cmake clang curl
RUN curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN ${HOME}/.cargo/bin/rustup default nightly
RUN ${HOME}/.cargo/bin/cargo install -f cargo-fuzz

ADD . /openmls
WORKDIR /openmls

## TODO: ADD YOUR BUILD INSTRUCTIONS HERE.
# RUN ${HOME}/.cargo/bin/cargo build --all
RUN cd fuzz && ${HOME}/.cargo/bin/cargo fuzz build

# Package Stage
FROM ubuntu:20.04


## TODO: Change <Path in Builder Stage>
COPY --from=builder openmls/openmls/fuzz/target/x86_64-unknown-linux-gnu/release/key_package_decode /
COPY --from=builder openmls/openmls/fuzz/target/x86_64-unknown-linux-gnu/release/mls_ciphertext_decode /
COPY --from=builder openmls/openmls/fuzz/target/x86_64-unknown-linux-gnu/release/mls_plaintext_decode /
COPY --from=builder openmls/openmls/fuzz/target/x86_64-unknown-linux-gnu/release/proposal_decode /
COPY --from=builder openmls/openmls/fuzz/target/x86_64-unknown-linux-gnu/release/welcome_decode /
