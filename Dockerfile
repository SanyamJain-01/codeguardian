FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# gitleaks: single binary
RUN curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz \
    | tar xz -C /usr/local/bin gitleaks

# semgrep in its own venv: same dependency conflict with fastapi as on your PC
RUN python -m venv /opt/semgrep && /opt/semgrep/bin/pip install --no-cache-dir semgrep \
 && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py agents.py CODING_STANDARDS.md ./

# PR code is untrusted: never handle it as root
RUN useradd --create-home app
USER app

# hosting platforms set $PORT; default to 8000 locally
CMD ["sh", "-c", "exec uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000}"]
