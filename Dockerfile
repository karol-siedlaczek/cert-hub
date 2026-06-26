FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY cert_hub ./cert_hub
COPY wsgi.py gunicorn.conf.py ./

# Build metadata (changes every build → kept after pip install to preserve the dependency layer cache)
ARG APP_VERSION=unknown
ARG GIT_SHA=unknown
ARG BUILD_DATE=unknown
ENV APP_VERSION=${APP_VERSION} \
    GIT_SHA=${GIT_SHA} \
    BUILD_DATE=${BUILD_DATE}

EXPOSE 8080

CMD ["gunicorn", "wsgi:app", "-c", "gunicorn.conf.py"]
