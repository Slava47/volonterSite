FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app.py .

RUN mkdir -p /app/data
RUN useradd -m -u 1000 webuser && chown -R webuser:webuser /app
USER webuser

CMD ["python", "app.py"]
