# libreleak - minimal secret scanner
# Multi-stage build for smallest possible image

FROM rust:1.83-alpine AS builder

RUN apk add --no-cache musl-dev git

WORKDIR /build
COPY Cargo.toml .
COPY src/ src/

# Build static binary with verification support
RUN cargo build --release --features verify

# Runtime image - alpine for git support
FROM alpine:3.21

# git: for cloning repos
# curl: for API calls in discovery
# coreutils: for timeout command in monitor
RUN apk add --no-cache git curl coreutils

COPY --from=builder /build/target/release/libreleak /usr/local/bin/libreleak
COPY scripts/scan-repo.sh /usr/local/bin/scan-repo.sh
COPY scripts/batch-scan.sh /usr/local/bin/batch-scan.sh
COPY scripts/discover-repos.sh /usr/local/bin/discover-repos.sh
COPY scripts/monitor.sh /usr/local/bin/monitor.sh
COPY scripts/compile-reports.py /usr/local/bin/compile-reports.py
COPY scripts/report-bounties.py /usr/local/bin/report-bounties.py

RUN chmod +x /usr/local/bin/scan-repo.sh \
    /usr/local/bin/batch-scan.sh \
    /usr/local/bin/discover-repos.sh \
    /usr/local/bin/monitor.sh \
    /usr/local/bin/compile-reports.py \
    /usr/local/bin/report-bounties.py

# Create directories
RUN mkdir -p /reports /scan /var/lib/libreleak

# Run as non-root
RUN adduser -D scanner && \
    chown -R scanner:scanner /reports /scan /var/lib/libreleak
USER scanner
WORKDIR /scan

ENTRYPOINT ["libreleak"]
CMD ["--help"]
