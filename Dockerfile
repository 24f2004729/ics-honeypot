# =============================================================================
#  Dockerfile — Enterprise Multi-Protocol ICS Honeypot
#  ---------------------------------------------------------------------------
#  Production-hardened, non-root container with CAP_NET_BIND_SERVICE
#  allowing port 502 binding without running as root.
# =============================================================================

FROM python:3.11-slim-bullseye AS base

# Install libcap2-bin for granting socket binding capabilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    libcap2-bin \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated non-root user
RUN groupadd -g 10001 honeypot && \
    useradd -u 10001 -g honeypot -m -s /bin/bash honeypot

WORKDIR /app

# Grant python binary capability to bind privileged ports (< 1024) without root
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/python3.11

# Copy project files
COPY honeypot/ /app/honeypot/
COPY main.py /app/
COPY README.md /app/

# Create logs directory with honeypot user ownership
RUN mkdir -p /app/logs && chown -R honeypot:honeypot /app

USER honeypot

# Default ports: Modbus TCP (502), DNP3 (20000), MQTT (1883)
EXPOSE 502 20000 1883

ENV PYTHONUNBUFFERED=1
ENV MODBUS_PORT=502
ENV DNP3_PORT=20000
ENV MQTT_PORT=1883

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import socket; s = socket.socket(); s.settimeout(2); s.connect(('127.0.0.1', 502)); s.close()" || exit 1

ENTRYPOINT ["python3", "main.py"]
