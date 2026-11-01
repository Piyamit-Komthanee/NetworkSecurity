FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py .
EXPOSE 8001
# gunicorn with several SYNC worker PROCESSES (not threads): CPython's re module holds the
# GIL while matching, so a threaded single-process server serializes and wedges on the first
# evil-regex request. Separate processes each accept and run independently, so N concurrent
# ReDoS attacks are genuinely accepted and held open at once (like a real multi-worker web
# app). --timeout 0 disables gunicorn's worker kill, so a persistent attack's connection is
# never closed by the server (the "never-closes" case); the experiment's PHASE 0 restart
# gives fresh workers each run. --preload shares the app via copy-on-write to save RAM.
CMD ["gunicorn", "-w", "8", "--preload", "--timeout", "0", "-b", "0.0.0.0:8001", "server:app"]
