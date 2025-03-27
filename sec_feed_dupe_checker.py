import csv
import os


class SecFeedDupeChecker:
    def __init__(self, logger, secops_feed_path, new_iocs) -> None:
        self.logger = logger
        self.secops_feed_path = secops_feed_path
        self.new_iocs = new_iocs
        self.approved_iocs = []

    def load_secops_feed_files(self):
        self.secops_feed_iocs = {}

        self.logger.info("Loading SecOps Feed Files")
        for filename in os.listdir(self.secops_feed_path):
            if filename.endswith(".csv"):
                file_path = os.path.join(self.secops_feed_path, filename)
                self.logger.info(f"Loading {file_path}")

                try:
                    with open(file_path, mode="r", encoding="utf-8") as file:
                        reader = csv.reader(file)
                        for row in reader:
                            if len(row) >= 4:
                                key = row[0].strip()
                                value = row[4].strip()
                                self.secops_feed_iocs[key] = value
                    self.logger.info("Loaded succesffully")
                except Exception as e:
                    self.logger.error(f"Failed to load file. Error: {e}")

    def find_new_entries(self):
        self.logger.info(f"Finding new IOCs")
        for ioc in self.new_iocs:
            fqdn = ioc[0]

            threat_id = self.secops_feed_iocs.get(fqdn, False)
            if threat_id is not False:
                new_threat_id = ioc[4]

                if threat_id.isdigit() and int(threat_id) >= 5220:
                    continue
                else:
                    if new_threat_id.isdigit() and int(new_threat_id) >= 5220:
                        self.approved_iocs.append(ioc)
            else:
                self.approved_iocs.append(ioc)

