# https://docs.docker.com/language/python/build-images/
FROM python:3.9.6-slim-buster

ENV FLASK_APP=login_form

WORKDIR /app
COPY . .

RUN python3 -m venv venv
RUN . venv/bin/activate
RUN pip3 install -e .


# Ensure zap-reports exists and is world-writable for ZAP
RUN chmod +x scripts/* && mkdir -p zap-reports && chmod 777 zap-reports

EXPOSE 5000

CMD ["gunicorn", "-b", "0.0.0.0:5000", "login_form:create_app()"]
