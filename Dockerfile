FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for networking and packet capture
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run the sniffer by default (requires --net=host and privileges when running)
ENTRYPOINT ["python", "-m", "sniffer.main"]
CMD ["--help"]
