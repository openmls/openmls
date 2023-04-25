FROM ubuntu:latest

RUN apt-get -y update
RUN apt-get -y install git make cmake clang curl zip pkg-config
RUN git clone https://github.com/Microsoft/vcpkg.git
RUN ./vcpkg/bootstrap-vcpkg.sh
ENV VCPKG_INSTALLATION_ROOT=/vcpkg
RUN git clone --depth 1 https://github.com/cisco/mlspp.git
WORKDIR /mlspp
RUN $VCPKG_INSTALLATION_ROOT/vcpkg install
RUN cmake -DCMAKE_TOOLCHAIN_FILE=$VCPKG_INSTALLATION_ROOT/scripts/buildsystems/vcpkg.cmake
RUN make
WORKDIR /mlspp/cmd/interop
RUN $VCPKG_INSTALLATION_ROOT/vcpkg install
RUN cmake -DCMAKE_TOOLCHAIN_FILE=$VCPKG_INSTALLATION_ROOT/scripts/buildsystems/vcpkg.cmake
RUN make
