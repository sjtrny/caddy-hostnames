FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

RUN apt update && apt install -y avahi-utils && apt clean

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY monitor.py ./

CMD ["python", "monitor.py"]