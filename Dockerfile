# Stage 1: Build & install Go recon tools
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

ENV CGO_ENABLED=0
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -v github.com/ffuf/ffuf/v2@latest

# Stage 2: Final lightweight runtime
FROM python:3.11-slim

# Install system dependencies (libpcap for naabu, ca-certificates for TLS)
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap-dev ca-certificates git && \
    rm -rf /var/lib/apt/lists/*

# Copy compiled Go binaries
COPY --from=builder /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=builder /go/bin/httpx /usr/local/bin/httpx
COPY --from=builder /go/bin/naabu /usr/local/bin/naabu
COPY --from=builder /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=builder /go/bin/gau /usr/local/bin/gau
COPY --from=builder /go/bin/ffuf /usr/local/bin/ffuf

WORKDIR /app

# Copy application files
COPY reconflow/ /app/reconflow/
COPY reconflow_v2.py /app/reconflow_v2.py
COPY reconflow.yaml.example /app/reconflow.yaml.example

ENTRYPOINT ["python", "/app/reconflow_v2.py"]
CMD ["--help"]
