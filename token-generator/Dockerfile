FROM python:3.13

WORKDIR /app
COPY . /app

RUN chown -R 1000:1000 /app 

RUN pip install --no-cache-dir -r requirements.txt

USER 1000
ENTRYPOINT ["python", "generate.py"]
