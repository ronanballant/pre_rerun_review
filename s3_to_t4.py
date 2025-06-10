from s3_client import S3Client
from config import (get_logger, destination_region,
    secops_s3_endpoint,
    secops_s3_bucket,
    secops_s3_aws_access_key,
    secops_s3_aws_secret_key,
    directory_prefix,
    ptld_dest_file_path,
    filtered_and_malicious_dest_path,
    unpopular_and_allowed_dest_path,
    detection_sources_dest_path,
    total_etp_traffic_dest_path,
    total_detected_etp_traffic_dest_path,
    total_carrier_traffic_dest_path,
    total_allowed_carrier_traffic_dest_path,
    total_detected_carrier_traffic_dest_path,
    action_id_totals_dest_path,
    carrier_totals_dest_path,
    low_detections_dest_file_path,
    already_exists_but_allowed_dest_file_path,
    ptld_local_file_path,
    filtered_and_malicious_local_file_path,
    unpopular_and_allowed_local_file_path,
    detection_sources_local_file_path,
    total_etp_traffic_local_file_path,
    total_detected_etp_traffic_local_file_path,
    total_carrier_traffic_local_file_path,
    total_allowed_carrier_traffic_local_file_path,
    total_detected_carrier_traffic_local_file_path,
    action_id_totals_local_file_path,
    carrier_totals_local_file_path,
    low_detections_local_file_path,
    already_exists_but_allowed_local_file_path,
    current_blacklist_dest_path,
    current_blacklist_local_file_path)

logger = get_logger("logs_s3_t4_transfer.txt")

s3_client = S3Client(
    logger,
    destination_region,
    secops_s3_endpoint,
    secops_s3_bucket,
    secops_s3_aws_access_key,
    secops_s3_aws_secret_key,
    directory_prefix,
)

s3_client.initialise_client()

s3_client.get_file(action_id_totals_dest_path)
s3_client.save_file_locally(action_id_totals_local_file_path)

s3_client.get_file(current_blacklist_dest_path)
s3_client.save_file_locally(current_blacklist_local_file_path)

s3_client.get_file(ptld_dest_file_path)
s3_client.save_file_locally(ptld_local_file_path)

s3_client.get_file(filtered_and_malicious_dest_path)
s3_client.save_file_locally(filtered_and_malicious_local_file_path)

s3_client.get_file(unpopular_and_allowed_dest_path)
s3_client.save_file_locally(unpopular_and_allowed_local_file_path)

s3_client.get_file(detection_sources_dest_path)
s3_client.save_file_locally(detection_sources_local_file_path)

s3_client.get_file(total_etp_traffic_dest_path)
s3_client.save_file_locally(total_etp_traffic_local_file_path)

s3_client.get_file(total_detected_etp_traffic_dest_path)
s3_client.save_file_locally(total_detected_etp_traffic_local_file_path)

s3_client.get_file(total_carrier_traffic_dest_path)
s3_client.save_file_locally(total_carrier_traffic_local_file_path)

s3_client.get_file(total_allowed_carrier_traffic_dest_path)
s3_client.save_file_locally(total_allowed_carrier_traffic_local_file_path)

s3_client.get_file(total_detected_carrier_traffic_dest_path)
s3_client.save_file_locally(total_detected_carrier_traffic_local_file_path)

s3_client.get_file(carrier_totals_dest_path)
s3_client.save_file_locally(carrier_totals_local_file_path)

s3_client.get_file(low_detections_dest_file_path)
s3_client.save_file_locally(low_detections_local_file_path)

s3_client.get_file(already_exists_but_allowed_dest_file_path)
s3_client.save_file_locally(already_exists_but_allowed_local_file_path)
