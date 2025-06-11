from datetime import datetime, timedelta

from benign_ioc import BenignIOC
from config import (broken_ioc_output_path, cert_path, key_path, current_blacklist_s3_path,
                    destination_region, directory_prefix, etp_repo_path, ioc_output_path,
                    get_logger, secops_feed_directory, secops_s3_aws_access_key, secops_s3_aws_secret_key,
                    secops_s3_bucket, secops_s3_endpoint, ssh_key_path)
from file_processor import FileProcessor
from mongo_manager import MongoManager
from git_repo_manager import GitRepoManager
from key_manager import KeyManager
from sec_feed_dupe_checker import SecFeedDupeChecker
from s3_client import S3Client

logger = get_logger("logs_avtest_ioc_collector.txt")

mongo_client = MongoManager(logger)
mongo_client.initialise_client()
mongo_client.test_connection()

current_time = datetime.now()
last_hour_timestamp = int((current_time - timedelta(hours=1)).timestamp())
logger.info(f"Last hour timestamp: {last_hour_timestamp}")

s3_client = S3Client(
    logger,
    destination_region,
    secops_s3_endpoint,
    secops_s3_bucket,
    secops_s3_aws_access_key,
    secops_s3_aws_secret_key,
    directory_prefix,
    last_hour_timestamp,
)

s3_client.initialise_client()
s3_client.collect_file_names()
s3_client.get_new_filenames()
s3_client.get_new_iocs()
iocs = s3_client.iocs
broken_iocs = s3_client.broken_iocs

if iocs:
    key_manager = KeyManager(logger, cert_path, key_path, ssh_key_path)
    key_manager.get_ssh_key("rballant-ssh")

    git_manager = GitRepoManager(logger, etp_repo_path)
    git_manager.start_ssh_agent()
    git_manager.add_ssh_key(ssh_key_path)
    git_manager.configure_user("rballant", "rballant@akamai.com")
    git_manager.checkout_master()
    git_manager.git_pull()

    duplication_checker = SecFeedDupeChecker(logger, secops_feed_directory, iocs)
    duplication_checker.load_secops_feed_files()
    duplication_checker.find_new_entries()
    approved_iocs = duplication_checker.approved_iocs
    dupes = len(iocs) - len(approved_iocs)
    logger.info(f"Found {dupes} duplications")
    
    if approved_iocs:
        ioc_writer = FileProcessor(logger, ioc_output_path)
        ioc_writer.append_file(approved_iocs)
        s3_client.write_file(ioc_output_path, current_blacklist_s3_path)

        git_manager.git_add([ioc_output_path])
        git_manager.git_commit("AVTest Pre-Rerun Review")
        git_manager.push_to_master()
        git_manager.get_pr_link()
        git_manager.kill_ssh_agent()
        key_manager.remove_ssh_keys()

        logger.info("Creating Mongo Inserts")
        for ioc in approved_iocs:
            indicator = BenignIOC(ioc)
            indicator.parse_indicator_details()
            indicator.create_mongo_inserts()

        logger.info("Adding inserts to Mongo")
        for ioc in BenignIOC.benign_iocs:
            mongo_client.insert_table_entry(ioc.mongo_insert)
    else:
        logger.info("No IOCs found")

    if broken_iocs:
        broken_ioc_writer = FileProcessor(
            logger, broken_ioc_output_path
        )
        broken_ioc_writer.append_file(broken_iocs)

logger.info("Process complete...")
