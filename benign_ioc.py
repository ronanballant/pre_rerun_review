from datetime import datetime


class BenignIOC:
    benign_iocs = []

    def __init__(self, blacklist_entry) -> None:
        self.blacklist_entry = blacklist_entry
        self.mongo_insert = {}
        BenignIOC.benign_iocs.append(self)

    def parse_indicator_details(self):
        fqdn = self.blacklist_entry[0]
        self.indicator_type = "domain"
        self.category = self.blacklist_entry[2]
        # known = self.blacklist_entry[3]
        self.threat_id = int(self.blacklist_entry[4])
        # attribution_description = self.blacklist_entry[5]
        # process = self.blacklist_entry[6]
        self.insertion_timestamp = int(self.blacklist_entry[7])
        # analyst = self.blacklist_entry[8]

        self.fqdn = fqdn[:-1] if fqdn.endswith(".") else fqdn
        self.timestamp_to_date()
        self.tool_source = "pre_rerun_ax_review"
        if self.category.lower() == "malware":
            self.matched_keyword = "genmalware"
            self.keywords = [self.matched_keyword]
            self.description = f"Used in Malware activity by Known Malware."
        elif self.category.lower() == "phishing":
            self.matched_keyword = "genphishing"
            self.keywords = [self.matched_keyword]
            self.description = f"Domain used in Phishing activity."

    def create_mongo_inserts(self):
        self.mongo_insert['record'] = self.fqdn
        self.mongo_insert['record_type'] = self.indicator_type
        self.mongo_insert['detection_date'] = self.date_string
        self.mongo_insert['detection_ts'] = self.insertion_timestamp
        self.mongo_insert['detection_source'] = self.tool_source
        self.mongo_insert['detection_url'] = None
        self.mongo_insert['category'] = self.category
        self.mongo_insert['threat_id'] = self.threat_id
        self.mongo_insert['description'] = self.description
        self.mongo_insert['matched_keyword'] = self.matched_keyword
        self.mongo_insert['keywords'] = self.keywords
        self.mongo_insert['external_links'] = None
        self.mongo_insert['report'] = f"daily_pre_rerun_ax_review_{self.date_string}"
    
    def timestamp_to_date(self):
        self.date_string = datetime.fromtimestamp(self.insertion_timestamp).strftime("%Y-%m-%d")

