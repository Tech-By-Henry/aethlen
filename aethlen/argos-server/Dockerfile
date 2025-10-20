FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# minimal runtime deps; wheels handle the rest
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl libstdc++6 && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# default; override with -e/compose as you like
ENV ARGOS_PACKAGES_DIR=/packages

EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
