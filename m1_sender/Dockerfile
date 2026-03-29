FROM python:3.11-slim

#sistem bagimliliklari
RUN apt-get update && apt-get install -y \
    net-tools \
    iputils-ping \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

#gereksinimler
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

#kodlar
COPY . .

#container'in kapanmamasi icin
CMD ["python", "main.py"]