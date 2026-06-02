FROM python:3.13-slim

WORKDIR /app

# System deps for reportlab (font rendering)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libfreetype6 \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

COPY . .

# Initialise the database on first run
RUN python -c "from app import app, init_db; init_db()"

EXPOSE 8000

CMD ["gunicorn", "--workers=2", "--threads=2", "--bind=0.0.0.0:8000", \
     "--timeout=60", "--access-logfile=-", "app:app"]
