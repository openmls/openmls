FROM rust:latest

RUN apt-get -y update && apt-get -y install protobuf-compiler

RUN useradd -m user
USER user
WORKDIR /home/user

WORKDIR /home/user/openmls/interop_client

ENV RUST_LOG=interop=info

EXPOSE 50051

ENTRYPOINT [ "cargo", "run", "--" ]
