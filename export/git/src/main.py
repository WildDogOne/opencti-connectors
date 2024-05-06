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
            config,
            False
        )
        if type(self.timeframes) is str:
            if "," in self.timeframes:
                self.timeframes = self.timeframes.split(",")
            else:
                self.timeframes = [self.timeframes]
        
        self.helper.log_info(f"self.export_file_csv_delimiter - {self.export_file_csv_delimiter}\nself.datafolder - {self.datafolder}\nself.git_user - {self.git_user}\nself.git_password - {self.git_password}\nself.git_repo - {self.git_repo}\nself.timeframes - {self.timeframes}\n")


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

    def _process_message(self, data):
        file_name = data["file_name"]
        export_scope = data["export_scope"]  # query or selection or single
        export_type = data["export_type"]  # Simple or Full
        file_markings = data["file_markings"]
        entity_id = data.get("entity_id")
        entity_type = data["entity_type"]
        main_filter = data.get("main_filter")
        access_filter = data.get("access_filter")

        if export_scope == "single":
            self.helper.connector_logger.info(
                "Exporting",
                {
                    "entity_id": entity_id,
                    "export_type": export_type,
                    "file_name": file_name,
                },
            )
            entity_data = self.helper.api_impersonate.stix_domain_object.read(
                id=entity_id
            )
            if entity_data is None:
                entity_data = self.helper.api_impersonate.stix_cyber_observable.read(
                    id=entity_id
                )
            if entity_data is None:
                raise ValueError(
                    "Unable to read/access to the entity, please check that the connector permission. Please note that all export files connectors should have admin permission as they impersonate the user requesting the export to avoir data leak."
                )
            entities_list = []
            object_ids = entity_data.get("objectsIds")
            if object_ids is not None and len(object_ids) != 0:
                export_selection_filter = {
                    "mode": "and",
                    "filterGroups": [
                        {
                            "mode": "or",
                            "filters": [
                                {
                                    "key": "id",
                                    "values": entity_data["objectsIds"],
                                }
                            ],
                            "filterGroups": [],
                        },
                        access_filter,
                    ],
                    "filters": [],
                }

                entities_sdo = self.helper.api_impersonate.stix_domain_object.list(
                    filters=export_selection_filter
                )
                entities_sco = self.helper.api_impersonate.stix_cyber_observable.list(
                    filters=export_selection_filter
                )

                entities_list = entities_sdo + entities_sco
                for entity in entities_list:
                    del entity["objectLabelIds"]
                del entity_data["objectsIds"]
            if "objectLabelIds" in entity_data:
                del entity_data["objectLabelIds"]
            entities_list.append(entity_data)
            csv_data = self.export_dict_list_to_csv(entities_list)
            self.helper.connector_logger.info(
                "Uploading",
                {
                    "entity_id": entity_id,
                    "export_type": export_type,
                    "file_name": file_name,
                    "file_markings": file_markings,
                },
            )
            self.helper.api.stix_domain_object.push_entity_export(
                entity_id, file_name, csv_data, file_markings
            )
            self.helper.connector_logger.info(
                "Export done",
                {
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "export_type": export_type,
                    "file_name": file_name,
                    "file_markings": file_markings,
                },
            )

        else:  # list export: export_scope = 'query' or 'selection'
            if export_scope == "selection":
                list_filters = "selected_ids"

                entity_data_sdo = self.helper.api_impersonate.stix_domain_object.list(
                    filters=main_filter
                )
                entity_data_sco = (
                    self.helper.api_impersonate.stix_cyber_observable.list(
                        filters=main_filter
                    )
                )
                entity_data_scr = (
                    self.helper.api_impersonate.stix_core_relationship.list(
                        filters=main_filter
                    )
                )
                entity_data_ssr = (
                    self.helper.api_impersonate.stix_sighting_relationship.list(
                        filters=main_filter
                    )
                )

                entities_list = (
                    entity_data_sdo
                    + entity_data_sco
                    + entity_data_scr
                    + entity_data_ssr
                )

                if entities_list is None:
                    raise ValueError(
                        "Unable to read/access to the entity, please check that the connector permission. Please note that all export files connectors should have admin permission as they impersonate the user requesting the export to avoir data leak."
                    )

            else:  # export_scope = 'query'
                list_params = data["list_params"]
                list_params_filters = list_params.get("filters")
                access_filter_content = access_filter.get("filters")

                self.helper.connector_logger.info(
                    "Exporting list: ",
                    {
                        "entity_type": entity_type,
                        "export_type": export_type,
                        "file_name": file_name,
                    },
                )

                if len(access_filter_content) != 0 and list_params_filters is not None:
                    export_query_filter = {
                        "mode": "and",
                        "filterGroups": [list_params_filters, access_filter],
                        "filters": [],
                    }
                elif len(access_filter_content) == 0:
                    export_query_filter = list_params_filters
                else:
                    export_query_filter = access_filter

                entities_list = self.helper.api_impersonate.stix2.export_entities_list(
                    entity_type=entity_type,
                    search=list_params.get("search"),
                    filters=export_query_filter,
                    orderBy=list_params["orderBy"],
                    orderMode=list_params["orderMode"],
                    getAll=True,
                )
                list_filters = json.dumps(list_params)

            if entities_list is not None:
                csv_data = self.export_dict_list_to_csv(entities_list)
                self.helper.log_info(
                    "Uploading: " + entity_type + "/" + export_type + " to " + file_name
                )
                if entity_type == "Stix-Cyber-Observable":
                    self.helper.api.stix_cyber_observable.push_list_export(
                        entity_id,
                        entity_type,
                        file_name,
                        file_markings,
                        csv_data,
                        list_filters,
                    )
                elif entity_type == "Stix-Core-Object":
                    self.helper.api.stix_core_object.push_list_export(
                        entity_id,
                        entity_type,
                        file_name,
                        file_markings,
                        csv_data,
                        list_filters,
                    )
                else:
                    self.helper.api.stix_domain_object.push_list_export(
                        entity_id,
                        entity_type,
                        file_name,
                        file_markings,
                        csv_data,
                        list_filters,
                    )
                self.helper.connector_logger.info(
                    "Export done",
                    {
                        "entity_type": entity_type,
                        "export_type": export_type,
                        "file_name": file_name,
                    },
                )
            else:
                raise ValueError("An error occurred, the list is empty")

        return "Export done"

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
        # if indicator_type.lower() == "artifact":
        #    filters["filters"].append(
        #        {"key": "objectLabel", "values": ["whitelist"]},
        #    )
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
        csv = self.export_dict_list_to_csv(data)
        # Check if the directory exists
        if not os.path.exists(file_path):
            # If the directory doesn't exist, create it
            os.makedirs(file_path)

        # Specify the path to the CSV file
        full_path = os.path.join(file_path, file_name + ".json")

        with open(full_path, "w") as f:
            json.dump(data, f, indent=4)

        # Write the data to the CSV file
        full_path = os.path.join(file_path, file_name + ".csv")
        with open(full_path, "w", newline="") as csvfile:
            csvfile.write(csv)

        add_file = [file_name + ".json", file_name + ".csv"]  # relative path from git root
        repo.index.add(add_file)  # notice the add function requires a list of paths
        repo.index.commit(f"Update {file_name}")
        origin = repo.remote(name='origin')
        origin.push()

    def cleanup(self, data):
        cleanups = [
            "id",
            "standard_id",
            "parent_types",
            "spec_version",
            "objectOrganization",
            "creators",
            "createdBy",
            "objectLabel",
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
                # else:
                #    print(x)
                #    quit()

        return output

    def initialize_git(self):
        remote = f"https://{self.git_user}:{self.git_password}@{self.git_repo}"
        if os.path.exists(self.datafolder):
            repo = Repo(self.datafolder)
        else:
            repo = Repo.clone_from(remote, self.datafolder)
        return repo



    def run(self):
        from pprint import pprint
        from dateutil.parser import parse
        repo = self.initialize_git()

        while True:
            self.helper.log_info("Connector started")
            # last_run = parse("2024-05-01").strftime("%Y-%m-%dT%H:%M:%SZ")

            #timeframes = [1, 7]
            #timeframes = [1]
            for timeframe in self.timeframes:
                last_run = (
                    datetime.now(tz=timezone.utc) - timedelta(hours=timeframe)
                ).strftime("%Y-%m-%dT%H:%M:%SZ")

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
    #connectorExportGit = ExportGit()
    #connectorExportGit.run()
    #quit()
    try:
        connectorExportGit = ExportGit()
        connectorExportGit.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
