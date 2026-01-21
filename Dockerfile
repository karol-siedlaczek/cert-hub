FROM python:3.12-alpine

WORKDIR /app

COPY app/ .

RUN pip3 install -r requirements.txt --no-cache-dir

CMD ["gunicorn", "wsgi:app"]


  #--access-logfile - \
  # --error-logfile - \
