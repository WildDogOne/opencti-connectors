FROM mcr.microsoft.com/playwright:v1.44.1-jammy
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/wild-connectors

# Install Python modules
# hadolint ignore=DL3003
RUN apt update 
RUN apt upgrade -y
RUN apt install git python3-pip -y
RUN cd /opt/wild-connectors && pip3 install --no-cache-dir -r requirements.txt 
RUN apt clean 
#RUN playwright install

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
