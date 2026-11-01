FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN pip install --no-cache-dir Flask==3.0.3
COPY server.py .
EXPOSE 8003
CMD ["python", "server.py"]
