FROM python:3.11-slim-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Go tools (subfinder, httpx, etc.)
ENV GO_VERSION=1.21.5
RUN curl -fsSL https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz | tar -xz -C /usr/local
ENV PATH="/usr/local/go/bin:${PATH}"

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install -v github.com/tomnomnom/assetfinder@latest && \
    go install -v github.com/tomnomnom/waybackurls@latest && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest
    go install -v github.com/tomnomnom/unfurl@latest && \
    go install -v github.com/tomnomnom/qsreplace@latest && \
    go install -v github.com/hahwul/dalfox/v2@latest && \
    go install -v github.com/punk-security/subzy@latest && \
    go install -v github.com/trufflesecurity/trufflehog/v3@latest && \
    pip install uro jsluice

# Final stage
FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy Go binaries from builder
COPY --from=builder /root/go/bin /usr/local/bin
COPY --from=builder /usr/local/go /usr/local/go
ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /app

# Install Python dependencies
COPY requirements.txt requirements-dev.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY python/ ./python/
COPY bash/ ./bash/
COPY sql/ ./sql/
COPY scripts/ ./scripts/
COPY .env.example ./.env

# Create directories
RUN mkdir -p /app/output /app/logs

# Set permissions
RUN chmod +x ./scripts/*.sh ./bash/wrappers/*.sh ./bash/lib/*.sh

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD ./scripts/healthcheck.sh

CMD ["python", "-m", "python.main"]