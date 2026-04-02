# base image python
FROM python:3.12-slim

RUN apt-get update && apt-get install -y telnet && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
COPY to_sw.py .
COPY telnet/ ./telnet/
COPY database/ ./database/

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "to_sw.py"]
