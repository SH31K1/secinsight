FROM python:3.12-slim

WORKDIR /app
COPY core /app/core
COPY cli /app/cli

RUN pip install --no-cache-dir -e /app/core -e /app/cli \
    && pip install --no-cache-dir matplotlib

ENTRYPOINT ["secinsight"]
CMD ["--help"]
