FROM python:3.12-slim

ARG APP_VERSION=unknown
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_VERSION=${APP_VERSION}

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY cert_hub ./cert_hub
COPY wsgi.py gunicorn.conf.py ./

EXPOSE 8080

CMD ["gunicorn", "wsgi:app", "-c", "gunicorn.conf.py"]
