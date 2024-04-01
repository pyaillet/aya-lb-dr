FROM ubuntu:22.04 AS lb

RUN apt-get update \
  && apt-get install -y iproute2 \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir -p /opt/lb-dr

COPY ./target/release/lb-dr /opt/lb-dr/lb-dr

ENV RUST_LOG=trace

# Wait for 3 second for the container to get its eth1 interface
CMD ["sh", "-c", "sleep 3 && /opt/lb-dr/lb-dr -i eth1"]

FROM nginx:stable AS backend

RUN apt-get update && apt-get install -y iproute2 && rm -rf /var/lib/apt/lists/*

