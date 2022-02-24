# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-present Open Networking Foundation
# Copyright 2019 Intel Corporation

# Multi-stage Dockerfile

# Stage bess-deps: fetch BESS dependencies
FROM ubuntu:20.04 AS bess-deps
ARG CPU=native
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get -y install \
        ca-certificates python3-pip software-properties-common \
        libelf-dev sudo kmod python3-pyverbs curl python-is-python3 \
        linux-tools-common linux-tools-generic linux-tools-`uname -r` \
        python3-pyverbs pkg-config git make apt-transport-https \
        g++ libunwind8-dev liblzma-dev zlib1g-dev \
        libpcap-dev libssl-dev libnuma-dev git \
        python3-scapy libgflags-dev libgoogle-glog-dev \
        libgraph-easy-perl libgtest-dev \
        libc-ares-dev libbenchmark-dev \
        libgtest-dev wget autoconf \
        automake cmake libtool \
        make ninja-build patch python3-pip \
        unzip virtualenv zip tar meson \
        libelf-dev libz-dev

ARG MAKEFLAGS
ENV PKG_CONFIG_PATH=/usr/lib64/pkgconfig

## Mellanox OFED Driver
ARG ENABLE_MLX
COPY install_mlx_ofed.sh .
RUN ./install_mlx_ofed.sh

WORKDIR /grpc
RUN git clone -b v1.44.0 https://github.com/grpc/grpc
RUN cd /grpc/grpc && git submodule init && git submodule update --recursive 
RUN cd /grpc/grpc && mkdir -p cmake/build && cd cmake/build && \
    cmake ../.. -DgRPC_INSTALL=ON              \
              -DCMAKE_BUILD_TYPE=Release       \
              -DgRPC_ABSL_PROVIDER=module     \
              -DgRPC_CARES_PROVIDER=module    \
              -DgRPC_PROTOBUF_PROVIDER=module \
              -DgRPC_RE2_PROVIDER=module      \
              -DgRPC_SSL_PROVIDER=package      \
              -DgRPC_ZLIB_PROVIDER=package &&  \
    make -j$(getconf _NPROCESSORS_ONLN) && sudo make install

RUN cd /grpc/grpc/third_party/protobuf && \
    git submodule update --init --recursive && \
    ./autogen.sh && ./configure && \
    make -j$(getconf _NPROCESSORS_ONLN) && sudo make install && sudo ldconfig

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get -y install \
        curl zip unzip tar meson

# The following packages are needed to run bessctl
RUN pip3 install --user protobuf grpcio scapy

# linux ver should match target machine's kernel
WORKDIR /libbpf
# ARG LIBBPF_VER=v0.3
ARG LIBBPF_VER=v0.7.0
RUN curl -L https://github.com/libbpf/libbpf/tarball/${LIBBPF_VER} | \
    tar xz -C . --strip-components=1 && \
    cd src && PREFIX=/usr LIBDIR=/usr/lib UAPIDIR=/usr/include make install && \
    PREFIX=/usr LIBDIR=/usr/lib UAPIDIR=/usr/include make install_uapi_headers && \
    ldconfig

WORKDIR /bpftool
COPY xdp-plugin xdp-scripts
RUN ./xdp-scripts/install-dependencies.sh && \
    rm -rf /bpftool

# RUN update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-12 100 && \
#     update-alternatives --install /usr/bin/clang clang /usr/bin/clang-12 100

WORKDIR /libxdp
ARG LIBXDP_VER=master
RUN git clone -b libxdp-cpp https://github.com/sebymiano/xdp-tools.git && \
    cd xdp-tools && ./configure && make libxdp && \
    sudo make libxdp install

FROM bess-deps AS bess-build
# BESS pre-reqs
WORKDIR /bess
ARG BESS_COMMIT=dpdk-2011-focal
RUN curl -L https://github.com/NetSys/bess/tarball/${BESS_COMMIT} | \
    tar xz -C . --strip-components=1
COPY patches/bess patches
COPY patches/bess-upf-ebpf/* patches/
RUN cat patches/* | patch -p1
RUN cp -a protobuf /protobuf

# Patch BESS, patch and build DPDK
COPY patches/dpdk/* deps/
RUN ./build.py dpdk

# Plugins
RUN mkdir -p plugins

## SequentialUpdate
RUN mv sample_plugin plugins

COPY upf-ebpf upf-ebpf
COPY upf-ebpf/protobuf/upf_ebpf_msg.proto /protobuf/
RUN mv upf-ebpf plugins/upf-ebpf

## Network Token
ARG ENABLE_NTF
ARG NTF_COMMIT=master
COPY install_ntf.sh .
RUN ./install_ntf.sh

# Build and copy artifacts
COPY core/ core/
COPY build_bess.sh .
RUN ./build_bess.sh && \
    cp bin/bessd /bin && \
    mkdir -p /bin/modules && \
    cp core/modules/*.so /bin/modules && \
    mkdir -p /opt/bess && \
    cp -r bessctl pybess /opt/bess && \
    cp -r core/pb /pb 

# Stage bess: creates the runtime image of BESS
FROM ubuntu:20.04 AS bess

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        gcc \
        libgraph-easy-perl \
        iproute2 \
        iptables \
        iputils-ping \
        tcpdump python3-pip \
        kmod python-is-python3 curl && \
    pip3 install --no-cache-dir \
        flask \
        grpcio \
        iptools \
        mitogen \
        protobuf \
        psutil \
        pyroute2 \
        scapy 

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get -y install \
        ca-certificates python3-pip software-properties-common \
        libelf-dev sudo kmod python3-pyverbs curl python-is-python3 \
        linux-tools-common linux-tools-generic linux-tools-`uname -r` \
        python3-pyverbs pkg-config git make apt-transport-https \
        g++ libunwind8-dev liblzma-dev zlib1g-dev \
        libpcap-dev libssl-dev libnuma-dev git \
        python3-scapy libgflags-dev libgoogle-glog-dev \
        libgraph-easy-perl libgtest-dev \
        libc-ares-dev libbenchmark-dev \
        libgtest-dev wget autoconf \
        automake cmake libtool \
        make ninja-build patch python3-pip \
        unzip virtualenv zip tar meson \
        libelf-dev libz-dev

## Mellanox OFED Driver
ARG ENABLE_MLX
COPY install_mlx_ofed.sh .
RUN ./install_mlx_ofed.sh

RUN rm -rf /var/lib/apt/lists/* && \
    apt-get --purge remove -y \
        gcc

# RUN mkdir -p /opt/mellanox/doca
# COPY mlx-doca/doca-host-repo-ubuntu2004_1.2.1-0.1.5.1.2.006.5.5.2.1.7.0_amd64.deb /opt/mellanox/doca

# RUN apt-get update && \
#     DEBIAN_FRONTEND=noninteractive apt-get install -y libvma

# RUN dpkg -i /opt/mellanox/doca/doca-host-repo-ubuntu2004_1.2.1-0.1.5.1.2.006.5.5.2.1.7.0_amd64.deb
# RUN apt-get update && \
#     DEBIAN_FRONTEND=noninteractive apt-get install -y doca-sdk doca-runtime doca-tools

COPY --from=bess-build /opt/bess /opt/bess
COPY --from=bess-build /bin/bessd /bin/bessd
COPY --from=bess-build /bin/modules /bin/modules
COPY conf /opt/bess/bessctl/conf
RUN ln -s /opt/bess/bessctl/bessctl /bin
ENV PYTHONPATH="/opt/bess"
WORKDIR /opt/bess/bessctl
ENTRYPOINT ["bessd", "-f"]

# Stage build bess golang pb
FROM golang AS protoc-gen
RUN go get github.com/golang/protobuf/protoc-gen-go

FROM bess-deps AS go-pb
COPY --from=protoc-gen /go/bin/protoc-gen-go /bin
RUN mkdir /bess_pb && \
    protoc -I /usr/include -I /protobuf/ \
        /protobuf/*.proto /protobuf/ports/*.proto \
        --go_opt=paths=source_relative --go_out=plugins=grpc:/bess_pb

FROM bess-deps AS py-pb
RUN pip3 install grpcio-tools==1.26
RUN mkdir /bess_pb && \
    python -m grpc_tools.protoc -I /usr/include -I /protobuf/ \
        /protobuf/*.proto /protobuf/ports/*.proto \
        --python_out=plugins=grpc:/bess_pb \
        --grpc_python_out=/bess_pb

FROM golang AS pfcpiface-build
ARG GOFLAGS
WORKDIR /pfcpiface

COPY go.mod /pfcpiface/go.mod
COPY go.sum /pfcpiface/go.sum

RUN if [[ ! "$GOFLAGS" =~ "-mod=vendor" ]] ; then go mod download ; fi

COPY . /pfcpiface
RUN CGO_ENABLED=0 go build $GOFLAGS -o /bin/pfcpiface ./pfcpiface

# Stage pfcpiface: runtime image of pfcpiface toward SMF/SPGW-C
FROM alpine AS pfcpiface
COPY conf /opt/bess/bessctl/conf
COPY conf/p4/bin/p4info.bin conf/p4/bin/p4info.txt conf/p4/bin/bmv2.json /bin/
COPY --from=pfcpiface-build /bin/pfcpiface /bin
ENTRYPOINT [ "/bin/pfcpiface" ]

# Stage pb: dummy stage for collecting protobufs
FROM scratch AS pb
COPY --from=bess-deps /bess/protobuf /protobuf
COPY --from=go-pb /bess_pb /bess_pb

# Stage ptf-pb: dummy stage for collecting python protobufs
FROM scratch AS ptf-pb
COPY --from=bess-deps /bess/protobuf /protobuf
COPY --from=py-pb /bess_pb /bess_pb

# Stage binaries: dummy stage for collecting artifacts
FROM scratch AS artifacts
COPY --from=bess /bin/bessd /
COPY --from=pfcpiface /bin/pfcpiface /
COPY --from=bess-build /bess /bess
