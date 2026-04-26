FROM python:3.11-slim

WORKDIR /app

# System deps for grpcio build (wheels may not exist for slim)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 6513 9090

CMD ["python3", "app.py", \
     "--leaf1-host", "192.168.122.20", \
     "--leaf2-host", "192.168.122.21", \
     "--gnmi-port",  "9339", \
     "--client-cert", "./certificate/generate/output_3snos/agent-ids/client.crt", \
     "--client-key",  "./certificate/generate/output_3snos/agent-ids/client.key", \
     "--client-ca",   "./certificate/generate/output_3snos/agent-ids/trustedCertificates.crt", \
     "--no-require-client-cert"]
