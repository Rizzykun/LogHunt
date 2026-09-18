# LogHunt - security log investigation toolkit
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

WORKDIR /app

# Dependencies first, so a code change does not reinstall them.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# The sample datasets are generated at build time rather than committed into
# the image, so the container always matches tools/generate_scenario.py.
RUN python tools/generate_scenario.py

# Run as a non-root user; nothing here needs privileges.
RUN useradd --create-home --uid 10001 loghunt && chown -R loghunt:loghunt /app
USER loghunt

EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/_stcore/health')"

CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
