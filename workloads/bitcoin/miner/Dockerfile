# syntax=docker/dockerfile:1
#
# Bitcoin Core node + bedrock-miner, statically built so the runtime layer
# has no extra libc dependencies. Drivers are baked at /opt/bedrock/drivers/
# where the bedrock-io kernel module enumerates them per-container for the
# ACTION_GET_WORKLOAD_DETAILS RPC.

FROM alpine:3.20 AS build
RUN apk add --no-cache gcc musl-dev
COPY miner.c /src/miner.c
RUN gcc -O2 -static -o /bedrock-miner /src/miner.c

FROM docker.io/bitcoin/bitcoin:latest
COPY --from=build /bedrock-miner /usr/local/bin/bedrock-miner
COPY drivers/ /opt/bedrock/drivers/
ENTRYPOINT ["/usr/local/bin/bedrock-miner"]
