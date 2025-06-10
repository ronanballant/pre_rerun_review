import boto3
import sys
import csv


class S3Client:
    def __init__(
        self,
        logger,
        destination_region, 
        secops_s3_endpoint, 
        secops_s3_bucket, 
        secops_s3_aws_access_key, 
        secops_s3_aws_secret_key, 
        directory_prefix,
        last_hour_timestamp=""
        ) -> None:

        self.logger = logger
        self.destination_region = destination_region
        self.secops_s3_endpoint = secops_s3_endpoint
        self.secops_s3_bucket = secops_s3_bucket
        self.secops_s3_aws_access_key = secops_s3_aws_access_key
        self.secops_s3_aws_secret_key = secops_s3_aws_secret_key
        self.directory_prefix = directory_prefix
        self.last_hour_timestamp = last_hour_timestamp
        self.endpoint_url = f"https://{self.secops_s3_endpoint}"
    
    def initialise_client(self):
        try:
            self.logger.info(f"Initialising S3 Client")
            self.s3_client = boto3.client(
                's3',
                endpoint_url=self.endpoint_url,
                aws_access_key_id=self.secops_s3_aws_access_key,
                aws_secret_access_key=self.secops_s3_aws_secret_key
            )
        except Exception as e:
            self.logger.error(f"Failed to initialise S3 client: {e}")
            sys.exit(1)

    def collect_file_names(self):
        self.logger.info(f"Collecting file names")
        self.filenames = []
        continuation_token = None

        while True:
            if continuation_token:
                response = self.s3_client.list_objects_v2(
                    Bucket=self.secops_s3_bucket, 
                    Prefix=self.directory_prefix, 
                    ContinuationToken=continuation_token
                )
            else:
                response = self.s3_client.list_objects_v2(
                    Bucket=self.secops_s3_bucket, 
                    Prefix=self.directory_prefix
                )

            if 'Contents' in response:
                self.filenames.extend([obj['Key'] for obj in response['Contents']])

            if response.get('IsTruncated'):  
                continuation_token = response['NextContinuationToken']
            else:
                self.logger.info(f"Collected {len(self.filenames)} files")
                break

    def get_new_filenames(self):
        self.logger.info(f"Finding new files")
        self.new_filenames = []
        if self.filenames:
            for file in self.filenames:
                filename = file.split("/")[-1]
                if filename.startswith("avtest_blacklist_") and filename.endswith('.csv'):
                    ts = int(filename.replace("avtest_blacklist_", "").replace(".csv", ""))
                    if ts >= self.last_hour_timestamp:
                        self.logger.info(f"File {file} added")
                        self.new_filenames.append(file)
            
            self.logger.info(f"Collected {len(self.new_filenames)} new files")
        else:
            self.logger.info(f"No files collected") 

    def get_new_iocs(self):
        self.logger.info(f"Finding new IOCs")
        self.iocs = []
        self.broken_iocs = []

        for file_key in self.new_filenames:
            self.logger.info(f"Processing {file_key}")
            response = self.s3_client.get_object(
                Bucket=self.secops_s3_bucket,
                Key=file_key
            )
            file_content = response['Body'].read().decode('utf-8')
            ioc_strings = file_content.strip().split("\n")
            for ioc_string in ioc_strings:
                if ioc_string:
                    broken_ioc = False
                    ioc_data = ioc_string.strip().split(",")

                    if ioc_data[5] == "AV-Test Malicious IOC":
                        if ioc_data[2].lower() == "malware":
                            ioc_data[5] = "Known Malware"
                        elif ioc_data[2].lower() == "phishing":
                            ioc_data[5] = "Phishing site"


                    for data in ioc_data:
                        if not data:
                            self.logger.info(f"No IOC data: {data}")
                            broken_ioc = True
                            break

                    domain = ioc_data[0]
                    if len(domain) < 3:
                        self.logger.info(f"Incorrect domain format: {domain}")
                        broken_ioc = True

                    if domain == ".":
                        self.logger.info(f"Incorrect domain format: {domain}")
                        broken_ioc = True

                    if not domain.endswith("."):
                        self.logger.info(f"Incorrect domain format - no ending '.': {domain}")
                        broken_ioc = True

                    if domain.startswith("."):
                        self.logger.info(f"Incorrect domain format - Starts with a '.': {domain}")
                        broken_ioc = True

                    period_count = domain.count(".")
                    if period_count <= 1:
                        self.logger.info(f"Incorrect domain format - less than 2 '.'s: {period_count} dots")
                        broken_ioc = True

                    comma_count = ioc_string.count(",")
                    if comma_count != 8:
                        self.logger.info(f"Incorrect entry format - not enough commas: {comma_count} commas")
                        broken_ioc = True

                    ioc_data_count = len(ioc_data)
                    if ioc_data_count != 9:
                        self.logger.info(f"Incorrect entry format - not enough field values: {ioc_data_count} commas")
                        broken_ioc = True

                    if broken_ioc is False:
                        self.iocs.append(ioc_data)
                    elif broken_ioc is True:
                        self.broken_iocs.append(ioc_data)

    def write_file(self, file_name, s3_output_path):        
        self.logger.info(f"Writing {file_name} to {self.secops_s3_bucket}/{s3_output_path}")
        self.s3_client.upload_file(file_name, self.secops_s3_bucket, s3_output_path)

    def get_file(self, file_path):
        self.logger.info(f"Requesting {file_path}")
        response = self.get_object(
            Bucket=self.secops_s3_bucket, 
            Key=file_path
        )
        self.file_content = response['Body'].read().decode('utf-8')
    
    def save_file_locally(self, filename):
        with open(filename, "w") as file:
            writer = csv.writer(file)
            writer.writerows(self.file_content)
    

