# --- builder -----------------------------------------------------------------
# Everything needed to build mlspp and its interop client (compilers, vcpkg,
# the cloned source tree, build objects) lives only in this stage; none of it
# ends up in the final image.
FROM ubuntu:latest AS builder

RUN apt-get -y update && apt-get -y install git make cmake clang curl zip pkg-config ninja-build \
  libicu-dev
# NOTE: cmd/interop/CMakeLists.txt does `find_package(ICU REQUIRED COMPONENTS uc data)` and links
# `ICU::uc ICU::data`, but ICU is not in its vcpkg.json manifest -- it must come from the system,
# hence libicu-dev above.

RUN useradd -m user

ENV HOME=/home/user
ENV VCPKG_FORCE_SYSTEM_BINARIES=1

USER user
WORKDIR ${HOME}

RUN git clone --recursive https://github.com/cisco/mlspp.git ${HOME}/mlspp
WORKDIR ${HOME}/mlspp
# Pin to a known-good main commit (main as of 2026-07-18) for reproducible builds.
RUN git checkout 92aaa4134fa45ec39957a7c81a342401fba7feb2 && git submodule update --init --recursive

# Use the vcpkg submodule that comes with mlspp
ENV VCPKG=${HOME}/mlspp/vcpkg
ENV VCPKG_ROOT=${HOME}/mlspp/vcpkg
RUN ${VCPKG}/bootstrap-vcpkg.sh -disableMetrics

# Install dependencies for the main mlspp library (using openssl_3 manifest)
WORKDIR ${HOME}/mlspp/alternatives/openssl_3
RUN ${VCPKG}/vcpkg install
WORKDIR ${HOME}/mlspp

# Build and install the main mlspp library
# Use openssl_3 as the TLS backend (matches the interop client's vcpkg.json)
RUN cmake . \
  -DCMAKE_TOOLCHAIN_FILE=$VCPKG/scripts/buildsystems/vcpkg.cmake \
  -DVCPKG_MANIFEST_DIR=alternatives/openssl_3 \
  -DCMAKE_INSTALL_PREFIX=${HOME}/mlspp_install
RUN make -j$(nproc)
RUN make install -j$(nproc)

# Build the interop client which has its own vcpkg.json
WORKDIR ${HOME}/mlspp/cmd/interop
# Install dependencies from vcpkg.json in this directory
RUN ${VCPKG}/vcpkg install
RUN cmake . -DCMAKE_TOOLCHAIN_FILE=$VCPKG/scripts/buildsystems/vcpkg.cmake -DMLSPP_DIR=${HOME}/mlspp_install
RUN make -j$(nproc)

# --- runtime -------------------------------------------------------------
# vcpkg's default Linux triplet (x64-linux) links its dependencies statically,
# so the built binary only needs libc/libstdc++ (from the base image) and ICU
# (linked dynamically, since it comes from the system package, not vcpkg) --
# not the compilers, vcpkg, or the cloned source/build tree from the builder
# stage.
FROM ubuntu:latest

RUN apt-get -y update && apt-get -y install --no-install-recommends libicu-dev \
  && rm -rf /var/lib/apt/lists/*

RUN useradd -m user
USER user
WORKDIR /home/user

COPY --from=builder --chown=user:user \
  /home/user/mlspp/cmd/interop/mlspp_client ./mlspp_client

ENTRYPOINT [ "./mlspp_client" ]
