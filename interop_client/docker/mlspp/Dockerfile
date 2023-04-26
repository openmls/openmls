FROM ubuntu:latest

RUN apt-get -y update
RUN apt-get -y install git make cmake clang curl zip pkg-config

RUN useradd -m user
USER user
WORKDIR /home/user

RUN git clone https://github.com/Microsoft/vcpkg.git
ENV VCPKG=/home/user/vcpkg
RUN $VCPKG/bootstrap-vcpkg.sh -disableMetrics

RUN git clone https://github.com/cisco/mlspp.git
WORKDIR mlspp
RUN git checkout 623acd0839d1117e8665b6bd52eecad1ce05438d
RUN $VCPKG/vcpkg install
RUN cmake . -DCMAKE_TOOLCHAIN_FILE=$VCPKG/scripts/buildsystems/vcpkg.cmake
RUN make
WORKDIR cmd/interop
RUN $VCPKG/vcpkg install
RUN cmake . -DCMAKE_TOOLCHAIN_FILE=$VCPKG/scripts/buildsystems/vcpkg.cmake
RUN make
