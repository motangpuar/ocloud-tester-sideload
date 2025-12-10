# Dockerfile
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    linux-perf \
    util-linux \
    procps \
    git \
    perl \
    ca-certificates \
    iproute2 \
    stress-ng \
    ethtool \
    python3 \
    python3-pip \
    python3-flask \
    python3-requests \
    tuned \
    sysstat \
    && rm -rf /var/lib/apt/lists/*

# Install FlameGraph
RUN git clone --depth=1 https://github.com/brendangregg/FlameGraph.git /opt/FlameGraph

# Add to PATH
ENV PATH="/opt/FlameGraph:${PATH}"

# Copy sideload server
COPY sideload_server.py /sideload_server.py

WORKDIR /workspace

EXPOSE 8080

CMD ["python3", "/sideload_server.py"]
