# Sandbox image: runs the POC in an isolated container. Everything inside is fake data and simulated tools.
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
# Non-root user, no shell access needed
RUN useradd -m runner && chown -R runner /app
USER runner
CMD ["python", "runner.py", "--list"]
