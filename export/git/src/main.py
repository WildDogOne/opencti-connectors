import csv
import io
import json
import os
import sys
import time
from datetime import datetime, timezone, timedelta
from git import Repo

import yaml
from pycti import OpenCTIConnectorHelper, get_config_variable


class ExportGit:
    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.interval = (
            get_config_variable(
                "CONNECTOR_INTERVAL",
                ["connector", "interval"],
                config,
                True,
            )
            * 60
        )
        self.export_file_csv_delimiter = get_config_variable(
            "EXPORT_FILE_CSV_DELIMITER",
            ["export-file-csv", "delimiter"],
            config,
            False,
            ",",
        )

        self.datafolder = get_config_variable(
            "CONNECTOR_DATAFOLDER",
            ["connector", "datafolder"],
            config,
            False,
            "/tmp/export-git/",
        )
        self.git_user = get_config_variable(
            "CONNECTOR_GIT_USER",
            ["connector", "git_user"],
            config,
            False
        )
        self.git_password = get_config_variable(
            "CONNECTOR_GIT_PASSWORD",
            ["connector", "git_password"],
            config,
            False
        )
        self.git_repo = get_config_variable(
            "CONNECTOR_GIT_REPO",
            ["connector", "git_repo"],
            config,
            False
        )
        self.timeframes = get_config_variable(
            "CONNECTOR_TIMEFRAMES",
            ["connector", "timeframes"],
            config
        )
        if type(self.timeframes) is str:
            if "," in self.timeframes:
                self.timeframes = self.timeframes.replace(" ","").split(",")
            else:
                self.timeframes = [self.timeframes]
        if type(self.timeframes) is not list:
            self.timeframes = [self.timeframes]
        
        


    def export_dict_list_to_csv(self, data):
        output = io.StringIO()
        headers = sorted(set().union(*(d.keys() for d in data)))
        if "hashes" in headers:
            headers = headers + [
                "hashes.MD5",
                "hashes_SHA-1",
                "hashes_SHA-256",
                "hashes_SHA-512",
                "hashes_SSDEEP",
            ]
        csv_data = [headers]
        for d in data:
            row = []
            for h in headers:
                if h.startswith("hashes_") and "hashes" in d:
                    hashes = {}
                    for hash in d["hashes"]:
                        hashes[hash["algorithm"]] = hash["hash"]
                    if h.split("_")[1] in hashes:
                        row.append(hashes[h.split("_")[1]])
                    else:
                        row.append("")
                elif h not in d:
                    row.append("")
                elif isinstance(d[h], str):
                    row.append(d[h])
                elif isinstance(d[h], int):
                    row.append(str(d[h]))
                elif isinstance(d[h], list):
                    if len(d[h]) > 0 and isinstance(d[h][0], str):
                        row.append(",".join(d[h]))
                    elif len(d[h]) > 0 and isinstance(d[h][0], dict):
                        rrow = []
                        for r in d[h]:
                            if "name" in r:
                                rrow.append(r["name"])
                            elif "definition" in r:
                                rrow.append(r["definition"])
                            elif "value" in r:
                                rrow.append(r["value"])
                            elif "observable_value" in r:
                                rrow.append(r["observable_value"])
                        row.append(",".join(rrow))
                    else:
                        row.append("")
                elif isinstance(d[h], dict):
                    if "name" in d[h]:
                        row.append(d[h]["name"])
                    elif "value" in d[h]:
                        row.append(d[h]["value"])
                    elif "observable_value" in d[h]:
                        row.append(d[h]["observable_value"])
                    else:
                        row.append("")
                else:
                    row.append("")
            csv_data.append(row)
        writer = csv.writer(
            output,
            delimiter=self.export_file_csv_delimiter,
            quotechar='"',
            quoting=csv.QUOTE_ALL,
        )
        writer.writerows(csv_data)
        return output.getvalue()


    def _get_indicators(self, indicator_type=None, last_run=None):
        # now = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        filters = {
            "mode": "and",
            "filters": [],
            "filterGroups": [],
        }
        if last_run:
            filters["filters"].append(
                {"key": "created_at", "values": last_run, "operator": "gt"},
            )
        if indicator_type:
            filters["filters"].append(
                {"key": "entity_type", "values": indicator_type, "operator": "eq"},
            )
        else:
            self.helper.log_error("No indicator type provided")
            quit()
        entities_list = self.helper.api_impersonate.stix2.export_entities_list(
            entity_type=indicator_type,
            # search="google",
            filters=filters,
            orderBy="created_at",
            orderMode="asc",
            getAll=True,
        )
        return entities_list

    def dump_data(self, data, file_path=None, file_name=None, repo=None):
        self.helper.log_info(f"Pulling latest changes from {self.git_repo}")
        repo.remotes.origin.pull()
        self.helper.log_info("Converting JSON data to CSV")
        csv = self.export_dict_list_to_csv(data)

        # Specify the path to the CSV file
        full_path = os.path.join(file_path, file_name + ".json")

        self.helper.log_info("Writing JSON Output")
        with open(full_path, "w") as f:
            json.dump(data, f, indent=4)

        self.helper.log_info("Writing CSV Output")
        # Write the data to the CSV file
        full_path = os.path.join(file_path, file_name + ".csv")
        with open(full_path, "w", newline="", encoding='utf-8') as csvfile:
            csvfile.write(csv)
        
        self.helper.log_info("Adding files to git and pushing to remote")
        add_file = [file_name + ".json", file_name + ".csv"]  # relative path from git root
        repo.index.add(add_file)  # notice the add function requires a list of paths
        repo.index.commit(f"Update {file_name}")
        origin = repo.remote(name='origin')
        response = origin.push()
        from pprint import pprint
        pprint(response)

    def cleanup(self, data):
        cleanups = [
            "id",
            "standard_id",
            "parent_types",
            "spec_version",
            "objectOrganization",
            "creators",
            "createdBy",
            "externalReferences",
            "indicators",
            "createdById",
            "objectMarkingIds",
            "objectLabelIds",
            "externalReferencesIds",
            "indicatorsIds",
            "mime_type",
            "importFiles",
            "importFilesIds",
        ]
        # Drop unnecessary fields
        for x in data:
            for y in cleanups:
                if y in x:
                    del x[y]

        # Remove TLP Red
        output = []
        for x in data:
            if "objectMarking" in x:
                if len(x["objectMarking"]) > 0:
                    for y in x["objectMarking"]:
                        if "definition" in y:
                            if (
                                y["definition"] == "TLP:GREEN"
                                or y["definition"] == "TLP:CLEAR"
                                #or y["definition"] == "PAP:GREEN"
                                #or y["definition"] == "PAP:CLEAR"
                            ):
                                output.append(x)
                                continue
        
        # Remove Whitelisted artifacts
        for x in output:
            if "objectLabel" in x:
                if len(x["objectLabel"]) > 0:
                    for y in x["objectLabel"]:
                        if y["value"] == "whitelist":
                            output.remove(x)
                            continue

        return output

    def initialize_git(self):
        remote = f"https://{self.git_user}:{self.git_password}@{self.git_repo}"
        if os.path.exists(self.datafolder):
            repo = Repo(self.datafolder)
        else:
            repo = Repo.clone_from(remote, self.datafolder)
        return repo



    def run(self):
        from dateutil.parser import parse
        repo = self.initialize_git()

        while True:
            self.helper.log_info("Connector started")
            # last_run = parse("2024-05-01").strftime("%Y-%m-%dT%H:%M:%SZ")

            #timeframes = [1, 7]
            #timeframes = [1]
            for timeframe in self.timeframes:
                if timeframe.endswith("h"):
                    timeframe = timeframe.replace("h", "")
                    last_run = (
                        datetime.now(tz=timezone.utc) - timedelta(hours=int(timeframe))
                    ).strftime("%Y-%m-%dT%H:%M:%SZ")
                elif timeframe.endswith("d"):
                    timeframe = timeframe.replace("d", "")
                    last_run = (
                        datetime.now(tz=timezone.utc) - timedelta(days=int(timeframe))
                    ).strftime("%Y-%m-%dT%H:%M:%SZ")
                else:
                    self.helper.log_error(f"Timeframe not supported: {timeframe}")
                    quit()

                current_state = self.helper.get_state()
                indicator_types = ["url", "domain-name", "IPv4-Addr", "Artifact"]
                for indicator_type in indicator_types:
                    entities_list = self._get_indicators(
                        indicator_type=indicator_type, last_run=last_run
                    )
                    entities_list = self.cleanup(entities_list)

                    self.dump_data(
                        entities_list,
                        file_path=self.datafolder,
                        file_name=indicator_type + "_" + str(timeframe) + "h",
                        repo=repo
                    )


            self.helper.log_info(
                f"Connector ended, sleeping for {self.interval/60} minutes"
            )
            self.helper.set_state(
                {
                    "last_run": datetime.now(tz=timezone.utc).timestamp(),
                }
            )
            time.sleep(self.interval)


if __name__ == "__main__":
    connectorExportGit = ExportGit()
    connectorExportGit.run()
    quit()
    try:
        connectorExportGit = ExportGit()
        connectorExportGit.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
