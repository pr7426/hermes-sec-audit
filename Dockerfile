FROM python:3.11-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
RUN addgroup --system app && adduser --system --ingroup app app && chown -R app:app /app
USER app
EXPOSE 10000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:10000/healthz')"
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "10000", "--proxy-headers"]
