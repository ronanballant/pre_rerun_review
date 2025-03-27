import csv


class FileProcessor:
    def __init__(self, logger, filename) -> None:
        self.filename = filename
        self.logger = logger

    def append_file(self, iocs):
        try:
            with open(self.filename, "a", newline="") as file:
                writer = csv.writer(file, delimiter=",", quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
                self.logger.info(f"Writing IoCs to {self.filename}")

                for row in iocs:
                    if row:
                        writer.writerow(row)
        except Exception as e:
            self.logger.error(f"Failed to append new IOCs to {self.filename}. Error: {e}")
