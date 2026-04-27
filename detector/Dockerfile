FROM python:3.11-slim

# Install iptables (needed for blocking)
RUN apt-get update && apt-get install -y \
    iptables \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all detector source files
COPY . .

# Create audit log file
RUN touch /app/audit.log

EXPOSE 8080

CMD ["python", "main.py"]
