# syntax=docker/dockerfile:1
#
# Tiny image for the integration-tests workload. It signals the bedrock VM
# ready (so the lab can take the initial checkpoint) and then idles, leaving
# the VM's lifetime to the lab. Built statically so the runtime layer stays
# minimal; alpine just provides /bin/sh for the compose wrapper command.

FROM alpine:3.20 AS build
RUN apk add --no-cache gcc musl-dev
# libvmcall.h is staged into this build context by build.sh (the shared
# guest hypercall library lives at guest/libvmcall.h, outside the context).
COPY libvmcall.h /src/libvmcall.h
COPY ready.c /src/ready.c
COPY test_feedback_buffers.c /src/test_feedback_buffers.c
COPY test_feedback_buffer_counter.c /src/test_feedback_buffer_counter.c
RUN gcc -O2 -static -o /bedrock-ready /src/ready.c
RUN gcc -O2 -static -o /test_feedback_buffers /src/test_feedback_buffers.c
RUN gcc -O2 -static -o /test_feedback_buffer_counter /src/test_feedback_buffer_counter.c

FROM alpine:3.20
COPY --from=build /bedrock-ready /usr/local/bin/bedrock-ready
# Lab-driven test drivers live under /opt/bedrock/drivers.
COPY --from=build /test_feedback_buffers /opt/bedrock/drivers/test_feedback_buffers
COPY --from=build /test_feedback_buffer_counter /opt/bedrock/drivers/test_feedback_buffer_counter
ENTRYPOINT ["/usr/local/bin/bedrock-ready"]
