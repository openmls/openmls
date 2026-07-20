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
RUN git checkout cfd450286d1bfd9cd2519b95c80f9771f94a5b1a

WORKDIR interop
RUN go mod edit -go=1.26
RUN go mod tidy -e
RUN go get google.golang.org/grpc@latest
RUN make run-go || echo "Build despite errors."
WORKDIR test-runner
COPY main.go.patch .
# TODO(#1366)
# Patch the test-runner so that it uses only the ciphersuites supported by OpenMLS.
RUN patch main.go main.go.patch
RUN go build

WORKDIR /home/user/mls-implementations/interop/test-runner

ENTRYPOINT [ "./test-runner" ]
