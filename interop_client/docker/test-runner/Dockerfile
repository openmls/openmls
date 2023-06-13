FROM ubuntu:latest

RUN apt-get -y update && apt-get -y install git make golang protoc-gen-go

RUN useradd -m user
USER user
WORKDIR /home/user

ENV GOPATH=/home/user/go
ENV PATH=$PATH:$GOPATH/bin

RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

RUN git clone https://github.com/mlswg/mls-implementations.git
WORKDIR mls-implementations
RUN git checkout f07090a844ebece12c064ce94ab853fd477db12f

WORKDIR interop
RUN go mod tidy -e
RUN make run-go || echo "Build despite errors."
WORKDIR test-runner
COPY main.go.patch .
# TODO(#1366)
# Patch the test-runner so that it uses only the ciphersuites supported by OpenMLS.
RUN patch main.go main.go.patch
RUN go build

WORKDIR /home/user/mls-implementations/interop/test-runner

ENTRYPOINT [ "./test-runner" ]
