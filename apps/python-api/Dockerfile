FROM python:3.12.9-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8080

WORKDIR /app
COPY --chown=65532:65532 app.py /app/app.py
USER 65532:65532
EXPOSE 8080
CMD ["python", "app.py"]
