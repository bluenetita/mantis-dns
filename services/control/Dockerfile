FROM python:3.12-slim
WORKDIR /app

COPY services/control .
RUN pip install --no-cache-dir -e ".[dev]"

EXPOSE 8000
CMD ["uvicorn", "mantis_control.main:app", "--host", "0.0.0.0", "--port", "8000"]
