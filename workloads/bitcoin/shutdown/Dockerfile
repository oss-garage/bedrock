# syntax=docker/dockerfile:1
#
# Tiny image whose only job is to hold the workload open until a `sleep`
# expires, then issue the bedrock shutdown VMCALL. Built statically so the
# runtime layer can be `scratch` if you want — alpine just gives us /bin/sh
# for the compose wrapper command.

FROM alpine:3.20 AS build
RUN apk add --no-cache gcc musl-dev
COPY shutdown.c /src/shutdown.c
RUN gcc -O2 -static -o /bedrock-shutdown /src/shutdown.c

FROM alpine:3.20
COPY --from=build /bedrock-shutdown /usr/local/bin/bedrock-shutdown
ENTRYPOINT ["/usr/local/bin/bedrock-shutdown"]
