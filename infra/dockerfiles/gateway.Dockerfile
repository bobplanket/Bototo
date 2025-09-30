FROM python:3.11-slim

ENV POETRY_VERSION=1.7.1 \
    POETRY_VIRTUALENVS_CREATE=false \
    PYTHONUNBUFFERED=1

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends build-essential curl git libpq-dev libsodium-dev && \
    curl -sSL https://install.python-poetry.org | python3 - --version ${POETRY_VERSION} && \
    ln -s /root/.local/bin/poetry /usr/local/bin/poetry && \
    pip install --upgrade pip && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml poetry.lock* /app/
RUN poetry install --no-root --only main
COPY . /app

EXPOSE 8000
CMD ["poetry", "run", "uvicorn", "apps.gateway_api.src.main:app", "--host", "0.0.0.0", "--port", "8000"]
