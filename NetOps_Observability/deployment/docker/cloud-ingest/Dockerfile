FROM python:3.12-slim
# google-auth: the GCP service-account OAuth flow needs RS256 signing that the
# stdlib cannot do — same dependency posture as boto3 (this is the lab poller
# container, not the stdlib-only Go backend).
RUN pip install --no-cache-dir boto3 kafka-python-ng==2.2.3 google-auth requests
COPY poller.py discover.py cloudmetrics.py azure.py gcp.py /
CMD ["python", "-u", "/poller.py"]
