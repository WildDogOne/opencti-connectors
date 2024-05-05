# Text Integration

The Connector can be configured with an URL pointing to a textfile with a certain type of indicator.
Never more than one indicator type per text file.

Known working sources:
- https://openphish.com/feed.txt
- =https://phishing.army/download/phishing_army_blocklist.txt


## Installation

### Requirements

- OpenCTI Platform >= 6.0.10

### Configuration

| Parameter                    | Docker envvar                | Mandatory | Description                                                                                   |
| ---------------------------- | ---------------------------- | --------- | --------------------------------------------------------------------------------------------- |
| `opencti_url`                | `OPENCTI_URL`                | Yes       | The URL of the OpenCTI platform.                                                              |
| `opencti_token`              | `OPENCTI_TOKEN`              | Yes       | The default admin token configured in the OpenCTI platform parameters file.                   |
| `connector_id`               | `CONNECTOR_ID`               | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                            |
| `connector_name`             | `CONNECTOR_NAME`             | Yes       | The Name of the connector as it will be shown in the UI                                       |
| `connector_scope`            | `CONNECTOR_SCOPE`            | Yes       | The scope is used as an identifyer of who pushed the data to the OpenCTI Instance             |
| `connector_confidence_level` | `CONNECTOR_CONFIDENCE_LEVEL` | Yes       | The default confidence level for created sightings (a number between 1 and 4).                |
| `connector_log_level`        | `CONNECTOR_LOG_LEVEL`        | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). |
| `connector_interval`         | `CONNECTOR_INTERVAL`         | Yes       | The interval in Minutes, make this appropriate to the source                                  |
| `connector_url`              | `CONNECTOR_URL`              | Yes       | The URL of the textfile                                                                       |
| `connector_ioc_type`         | `CONNECTOR_IOC_TYPE`         | Yes       | The IOC Type, should be one of: domain, ip, url, sha256, md5                                  |
| `connector_labels`           | `CONNECTOR_LABELS`           | Yes       | The Labels to attach, comma seperated array                                                   |
| `connector_description`      | `CONNECTOR_DESCRIPTION`      | Yes       | The description which should be added to the indicators/observables                           |



### Debugging

<!-- Any additional information to help future users debug and report detailed issues concerning this connector -->

### Additional information

<!--
Any additional information about this connector
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->