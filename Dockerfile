FROM ubuntu:bionic

# Install necessary dependencies for Rust
RUN apt-get update && \
    apt-get install -y curl build-essential && \
    apt-get clean

# Install Rust using rustup
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Add Cargo's bin directory to the PATH for subsequent commands in the same layer
ENV PATH="/root/.cargo/bin:$PATH"

WORKDIR /volume

RUN apt-get update && apt install -y \
    libltdl-dev \
    pkg-config \
    autoconf-archive \
    libssl-dev \
    libjson-c-dev \
    libcurl4-openssl-dev \
    linux-headers-generic \
    libpcsclite-dev \
    git \
    clang \
    llvm

RUN cargo install wasm-pack