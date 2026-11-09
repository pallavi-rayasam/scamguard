FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10001 scanner
WORKDIR /app
COPY url_scanner/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY url_scanner /app/url_scanner
COPY data/seed/organization_domains.json /app/data/seed/organization_domains.json
USER scanner
EXPOSE 8001
CMD ["sh", "-c", "uvicorn url_scanner.main:app --host 0.0.0.0 --port ${PORT:-8001}"]
