FROM python:3.11-slim AS base
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    net-tools \
    iputils-ping \
    arp-scan \
    && rm -rf /var/lib/apt/lists/*

FROM base AS builder
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM base AS final
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH
COPY . .
RUN pip install --no-cache-dir -e .
EXPOSE 8080
CMD ["python", "-m", "scanner", "web", "--host", "0.0.0.0", "--port", "8080"]
