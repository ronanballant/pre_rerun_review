from pymongo import MongoClient

import tb_cred


class MongoManager:
    def __init__(self, logger) -> None:
        self.mongo_db_cred = tb_cred.login["mongo_int"]
        self.logger = logger
        
    def initialise_client(self):
        self.logger.info(f"Initialising Mongo Connection")
        self.client = MongoClient(self.mongo_db_cred)
        self.db = self.client.secops
        self.ioc_v2_table = self.db.ioc_v2

    def test_connection(self):
        self.logger.info(f"Testing Mongo Connection")
        try:
            self.client.server_info()
            self.logger.info(f"Mongo connection succesful")
        except Exception as e:
            self.logger.error(f"Mongo connection failed: {e}")

    def insert_table_entry(self, entry):
        self.ioc_v2_table.insert_one(entry)
    
        