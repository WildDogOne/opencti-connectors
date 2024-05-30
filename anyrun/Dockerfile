FROM python:3.11-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/wild-connectors

# Install Python modules
# hadolint ignore=DL3003
RUN apk update 
RUN apk upgrade 
RUN apk --no-cache add git build-base libmagic libxslt libxslt-dev libxml2 libxml2-dev 
RUN cd /opt/wild-connectors && pip3 install --no-cache-dir -r requirements.txt 
RUN apk del git build-base 
RUN rm -rf /var/cache/apk/*
RUN playwright install

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]