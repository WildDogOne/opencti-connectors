import os
import json
import time
from datetime import datetime, timezone

import requests
import stix2
import stix2.hashes
import yaml
from pycti import (
    Identity,
    Indicator,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)
from playwright.sync_api import sync_playwright


class Anyrun:
    """
    Downloads Text file from URL
    Enumerates Indicators and Observables from that text
    Does local deduplication of IOCs
    """

    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)
        name = get_config_variable(
            "CONNECTOR_NAME", ["connector", "name"], config
        ).capitalize()
        self.author = stix2.Identity(
            id=Identity.generate_id(name, "organization"),
            name=name,
            identity_class="organization",
        )

        self.labels = get_config_variable(
            "CONNECTOR_LABELS",
            ["connector", "labels"],
            config,
        )
        if type(self.labels) is str:
            if "," in self.labels:
                self.labels = self.labels.split(",")
            else:
                self.labels = [self.labels]

        self.description = get_config_variable(
            "CONNECTOR_DESCRIPTION",
            ["connector", "description"],
            config,
        )
        self.interval = (
            get_config_variable(
                "CONNECTOR_INTERVAL",
                ["connector", "interval"],
                config,
                True,
            )
            * 60
        )
        self.update_existing_data = get_config_variable(
            "CONNECTOR_UPDATE_EXISTING_DATA",
            ["connector", "update_existing_data"],
            config,
        )
        self.deduplication = get_config_variable(
            "CONNECTOR_DEDUPLICATE",
            ["connector", "deduplicate"],
            config,
        )
        if self.deduplication is not False:
            self.deduplication = True

        self.deduplication_folder = "/tmp/deduplication"
        self.deduplication_file = "indicators.json"

    def get_anyrun_urls(self, url=None):
        if url is None:
            url = "https://any.run/malware-trends/"

        with sync_playwright() as p:
            browser = p.chromium.launch()
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
            )
            page = context.new_page()
            page.goto(url)
            hrefs = page.eval_on_selector_all(
                ".table-list__item a", "nodes => nodes.map(n => n.href)"
            )
            browser.close()

        return hrefs

    def get_anyrun_iocs(self, url=None):
        if url is None:
            self.helper.log_error("No URL provided")
            quit()
        with sync_playwright() as p:
            browser = p.chromium.launch()
            context = browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
            )
            page = context.new_page()
            page.goto(url)

            try:
                ipAddresses = [
                    el.inner_text()
                    for el in page.query_selector_all("#ipData .list__item")
                ]
            except:
                ipAddresses = []
            try:
                hashes = [
                    el.inner_text()
                    for el in page.query_selector_all("#hashData .list__item")
                ]
            except:
                hashes = []
            try:
                domains = [
                    el.inner_text()
                    for el in page.query_selector_all("#domainData .list__item")
                ]
            except:
                domains = []
            try:
                urls = [
                    el.inner_text()
                    for el in page.query_selector_all("#urlData .list__item")
                ]
            except:
                urls = []

            browser.close()
        sha256 = []
        for hash in hashes:
            if len(hash) == 64:
                sha256.append(hash)
            else:
                print(f"Invalid SHA256 hash: {hash}")
        iocs = {"ipv4": ipAddresses, "sha256": sha256, "domain": domains, "url": urls}
        return iocs

    def dedup(self, iocs):
        if not os.path.exists(self.deduplication_folder):
            os.makedirs(self.deduplication_folder)

        filename = self.deduplication_folder + "/" + self.deduplication_file
        existing = []
        if os.path.exists(filename):
            with open(filename, "r") as f:
                existing = json.load(f)
        else:
            self.helper.log_info(
                f"{filename} does not exist. No deduplication will be performed."
            )

        cleaned = {}
        for ioc_type in iocs:
            x = []
            for ioc in iocs[ioc_type]:
                if ioc not in existing:
                    existing.append(ioc)
                    x.append(ioc)
            cleaned[ioc_type] = x


        with open(filename, 'w') as f:
            json.dump(existing, f, ensure_ascii=False, indent=4)
        return cleaned

    def run(self):
        """Running component of class"""
        while True:
            try:
                current_state = self.helper.get_state()
                now = datetime.now(tz=timezone.utc)
                friendly_name = "Wild Connectors run @ " + now.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )
                if current_state is not None and "last_run" in current_state:
                    last_seen = datetime.fromtimestamp(current_state["last_run"])
                    self.helper.log_info(f"Connector last ran at: {last_seen} (UTC)")
                else:
                    self.helper.log_info("Connector has never run")

                urls = self.get_anyrun_urls()
                for url in urls:
                    threat = url.split("/")[-1]
                    self.helper.log_info(f"Processing URL: {threat}")
                    iocs = self.get_anyrun_iocs(url)
                    if self.deduplication:
                        iocs = self.dedup(iocs)
                    #quit()
                    labels = self.labels.append(threat)
                    for ioc_type in iocs:
                        self.helper.log_info(f"Processing {ioc_type}")
                        if len(iocs[ioc_type]) == 0:
                            continue
                        observables = self.create_observables(
                            iocs[ioc_type],
                            ioc_type=ioc_type,
                            description=self.description,
                            labels=labels,
                        )
                        indicators = self.create_indicators(
                            observables,
                            ioc_type=ioc_type,
                            description=self.description,
                            labels=labels,
                        )
                        relationships = self.create_relationships(
                            observables, indicators, ioc_url=url
                        )
                        bundle = self.create_bundle(
                            observables, indicators, relationships
                        )
                        self.send_bundle(bundle, work_id)
                message = (
                    "Connector successfully run ("
                    + str((len(indicators) + len(observables) + len(relationships)))
                    + " events have been processed), storing last_run as "
                    + str(now)
                )
                self.helper.log_info(message)

                self.helper.set_state(
                    {
                        "last_run": now.timestamp(),
                    }
                )
                time.sleep(self.interval)

            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                exit(0)

            except Exception as exception:
                self.helper.log_error(str(exception))
                time.sleep(self.interval)

    def get_txt(self, url=None):
        """
        Retrieves response from provided URL and grabs URLs  from resulting HTML

        :param url: URL for list of URLs
        :return: :class:`List` of URLs
        """
        self.helper.log_info("Getting URLs from text file")
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
        }
        response = requests.get(url, headers=headers)
        if response.ok:
            response_text = response.text
        else:
            return response.raise_for_status()

        text_lines = response_text.split("\n")
        urls = []
        for line in text_lines:
            # Ignore lines starting with '#' and empty lines
            if not line.startswith("#") and not line == "":
                urls.append(line)
        return urls

    def create_observables(self, iocs, ioc_type=None, description=None, labels=None):
        """
        Creates STIX URL Observables from provided list of URLs

        :param urls: List of URLs
        :return: :class:`List` of STIX URL Observables
        """
        # if observable["type"] == "domain":
        #    type_observable = "Domain-Name.value"
        # elif observable["type"] == "ip":
        #    type_observable = "IPv4-Addr.value"
        # elif observable["type"] == "url":
        #    type_observable = "Url.value"
        # elif observable["type"] == "sha256":
        #    type_observable = "file.hashes.sha-256"
        # elif observable["type"] == "md5":
        #    type_observable = "file.hashes.md5"

        self.helper.log_info("Creating STIX Observables")
        observables = []
        for ioc in iocs:
            if ioc_type == "url":
                observable = stix2.URL(
                    value=ioc,
                    object_marking_refs=[stix2.TLP_WHITE],
                    custom_properties={
                        "x_opencti_description": description,
                        "x_opencti_created_by_ref": f"{self.author.id}",
                        "x_opencti_labels": labels,
                    },
                )
            elif ioc_type == "domain":
                observable = stix2.DomainName(
                    value=ioc,
                    object_marking_refs=[stix2.TLP_WHITE],
                    custom_properties={
                        "x_opencti_description": description,
                        "x_opencti_created_by_ref": f"{self.author.id}",
                        "x_opencti_labels": labels,
                    },
                )
            elif ioc_type == "ipv4":
                observable = stix2.IPv4Address(
                    value=ioc,
                    object_marking_refs=[stix2.TLP_WHITE],
                    custom_properties={
                        "x_opencti_description": description,
                        "x_opencti_created_by_ref": f"{self.author.id}",
                        "x_opencti_labels": labels,
                    },
                )
            elif ioc_type == "sha256":
                observable = stix2.File(
                    name=ioc,
                    hashes={"SHA-256": ioc},
                    object_marking_refs=[stix2.TLP_WHITE],
                    custom_properties={
                        "x_opencti_description": description,
                        "x_opencti_created_by_ref": f"{self.author.id}",
                        "x_opencti_labels": labels,
                    },
                )
            else:
                self.helper.log_error("Failed to determine IOC type")
                quit()

            observables.append(observable)
        return observables

    def create_indicators(
        self, observables, ioc_type=None, description=None, labels=None
    ):
        """
        Creates STIX Indicators from provided STIX observables

        :param observables: List of STIX URL Observables
        :return: :class:`List` of STIX Indicators
        """
        self.helper.log_info("Creating STIX Indicators")

        if ioc_type == "domain":
            type_ioc = "Domain-Name:value"
        elif ioc_type == "ipv4":
            type_ioc = "IPv4-Addr:value"
        elif ioc_type == "url":
            type_ioc = "Url:value"
        elif ioc_type == "sha256":
            type_ioc = "File:hashes.'SHA-256'"
        elif ioc_type == "md5":
            type_ioc = "File:hashes.'MD5'"
        else:
            self.helper.log_error("Failed to determine IOC type")
            quit()
        indicators = []
        for observable in observables:
            if ioc_type == "sha256":
                value = observable.name
            else:
                value = observable.value
            pattern = f"[{type_ioc} = '{value}']"
            indicator = stix2.Indicator(
                id=Indicator.generate_id(pattern),
                name=value,
                description=description,
                created_by_ref=f"{self.author.id}",
                confidence=self.helper.connect_confidence_level,
                pattern_type="stix",
                pattern=pattern,
                labels=labels,
                object_marking_refs=[stix2.TLP_WHITE],
                custom_properties={
                    "x_opencti_main_observable_type": type_ioc.split(":")[0],
                },
            )
            indicators.append(indicator)
        return indicators

    def create_relationships(self, observables, indicators, ioc_url=None):
        """
        Creates a list of STIX Relationships between the given lists of STIX Observables and Indicators

        :param observables: List of STIX Observables objects
        :param indicators: List of STIX Indicators objects
        :return: List of STIX Relationship objects
        """
        self.helper.log_info("Creating STIX Relationships")
        relationships = []
        external_reference = stix2.ExternalReference(
            source_name="Anyrun Malware Trends",
            url=ioc_url,
        )
        for i in range(len(observables)):
            relationship = stix2.Relationship(
                id=StixCoreRelationship.generate_id(
                    "based-on", indicators[i].id, observables[i].id
                ),
                relationship_type="based-on",
                source_ref=indicators[i].id,
                target_ref=observables[i].id,
                object_marking_refs=[stix2.TLP_WHITE],
                external_references=[external_reference],
            )
            relationships.append(relationship)
        return relationships

    def create_bundle(self, observables, indicators, relationships):
        """Creates serialized STIX Bundle object from the provided lists of STIX Observables, Indicators, and Relationships

        :param indicators: List of STIX Indicator objects
        :return: Serialized STIX Bundle object
        """
        self.helper.log_info("Creating STIX Bundle")
        objects = [self.author]
        for observable in observables:
            objects.append(observable)
        for indicator in indicators:
            objects.append(indicator)
        for relationship in relationships:
            objects.append(relationship)
        bundle = self.helper.stix2_create_bundle(objects)
        return bundle

    def send_bundle(self, bundle, work_id):
        """
        Attempts to send serialized STIX Bundle to OpenCTI client

        :param bundle: Serialized STIX Bundle
        """
        self.helper.log_info("Sending STIX Bundle")
        try:
            self.helper.send_stix2_bundle(
                bundle, work_id=work_id, update=self.update_existing_data
            )
        except:
            time.sleep(60)
            try:
                self.helper.send_stix2_bundle(
                    bundle, work_id=work_id, update=self.update_existing_data
                )
            except Exception as e:
                self.helper.log_error(str(e))


if __name__ == "__main__":
    Anyrun = Anyrun()
    Anyrun.run()
    try:
        Anyrun = Anyrun()
        Anyrun.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
