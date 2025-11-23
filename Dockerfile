FROM python:3.9-slim

WORKDIR /app

# Установка зависимостей системы
RUN apt-get update && apt-get install -y \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Создание пользователя и директорий заранее
RUN useradd -m -u 1000 webuser && \
    mkdir -p /app/data && \
    chown -R webuser:webuser /app

# Копирование requirements и установка Python зависимостей
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копирование приложения и установка прав
COPY app.py .
RUN chown webuser:webuser app.py

USER webuser

# Запуск приложения
CMD ["python", "app.py"]
