FROM python:3.12-alpine

WORKDIR /app

COPY app/ .

RUN pip3 install -r requirements.txt --no-cache-dir

CMD ["gunicorn", "--access-logfile", "logs/access.log", "--error-logfile", "logs/error.log", "-w", "4", "-b", "0.0.0.0:8080", "wsgi:app"]


  #--access-logfile - \
  # --error-logfile - \
