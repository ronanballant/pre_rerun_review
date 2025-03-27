import base64
import os

import get_az_secret


class KeyManager:
    def __init__(self, logger, cert_path, key_path, ssh_key_path, analyst="rballant") -> None:
        self.analyst = "rballant"
        self.cert_path = cert_path
        self.key_path = key_path
        self.ssh_key_path = ssh_key_path
        self.logger = logger

    def remove_personal_keys(self):
        os.remove(self.cert_path)
        os.remove(self.key_path)
    
    def remove_ssh_keys(self):
        self.logger.info("Removing SSH keys")
        os.remove(self.ssh_key_path)

    def decode_key(self, key):
        self.logger.info("Decoding Key")
        return base64.b64decode(key)

    def get_ssh_key(self, key_name):
        self.logger.info(f"Getting SSH key {key_name}")
        try:
            encoded_ssh_key = get_az_secret.get_az_secret(key_name)
            ssh_key = self.decode_key(encoded_ssh_key).decode("utf-8")
            with open(self.ssh_key_path, "w") as f:
                f.write(ssh_key.replace("\\n", "\n").replace("\n ", "\n"))

            os.chmod(self.ssh_key_path, 0o600)
        except:
            encoded_ssh_key = get_az_secret.get_az_secret("rballant-ssh")
            ssh_key = self.decode_key(encoded_ssh_key).decode("utf-8")
            with open(self.ssh_key_path, "w") as f:
                f.write(ssh_key.replace("\\n", "\n").replace("\n ", "\n"))
            
            os.chmod(self.ssh_key_path, 0o600)

    def get_personal_keys(self):
        self.logger.info("Getting Personal keys")
        try:
            encoded_cert = get_az_secret.get_az_secret(self.cert_name)
            cert = self.decode_key(encoded_cert).decode("utf-8")
            with open(self.cert_path, "w") as f:
                f.write(cert.replace("\\n", "\n").replace("\n ", "\n"))
        
            encoded_key = get_az_secret.get_az_secret(self.key_name)
            key = self.decode_key(encoded_key).decode("utf-8")
            with open(self.key_path, "w") as f:
                f.write(key.replace("\\n", "\n").replace("\n ", "\n"))
        except:
            encoded_cert = get_az_secret.get_az_secret("rballant-crt")
            cert = self.decode_key(encoded_cert).decode("utf-8")
            with open(self.cert_path, "w") as f:
                f.write(cert.replace("\\n", "\n").replace("\n ", "\n"))
        
            encoded_key = get_az_secret.get_az_secret("rballant-key")
            key = self.decode_key(encoded_key).decode("utf-8")
            with open(self.key_path, "w") as f:
                f.write(key.replace("\\n", "\n").replace("\n ", "\n"))
