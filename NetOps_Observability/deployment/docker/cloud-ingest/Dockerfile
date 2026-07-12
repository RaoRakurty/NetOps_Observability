FROM python:3.12-slim
RUN pip install --no-cache-dir boto3 kafka-python-ng==2.2.3
COPY poller.py /poller.py
CMD ["python", "-u", "/poller.py"]
