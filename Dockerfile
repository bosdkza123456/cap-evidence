# Controlled harness image; not a production or hostile-package sandbox.
# Version tags are explicit but not immutable digests; validate/pin before release.
ARG GO_IMAGE=golang:1.26.8-bookworm
FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY internal ./internal
COPY adapters ./adapters
COPY cmd/rawpreview ./cmd/rawpreview
RUN GOTOOLCHAIN=local CGO_ENABLED=0 go build -mod=vendor -trimpath -o /out/rawpreview ./cmd/rawpreview

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 gcc libc6-dev strace bubblewrap ca-certificates \
    && apt-get clean
WORKDIR /app
COPY --from=build /out/rawpreview /usr/local/bin/rawpreview
COPY experiments/linux-collector/collector.py experiments/linux-collector/harness.py \
     experiments/linux-collector/workload.c ./experiments/linux-collector/
ENV PYTHONDONTWRITEBYTECODE=1
USER 10001:10001
ENTRYPOINT ["python3", "experiments/linux-collector/harness.py", "--preview", "/usr/local/bin/rawpreview"]
