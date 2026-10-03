FROM python:3.12-slim

WORKDIR /app

# System deps for psycopg + reportlab (fonts) 
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

COPY core /app/core
COPY backend/requirements.txt /app/backend/requirements.txt

RUN pip install --no-cache-dir -e /app/core \
    && pip install --no-cache-dir -r /app/backend/requirements.txt

COPY backend/app /app/backend/app
COPY backend/alembic.ini /app/backend/alembic.ini
COPY backend/alembic /app/backend/alembic

WORKDIR /app/backend
ENV PYTHONPATH=/app/backend:/app/core

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
