from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64
import uuid
import os
import yaml
from Crypto.PublicKey import RSA

class RSAgen:
    def __init__(self, key_size=2048):
        self.key = RSA.generate(key_size)
        self.private_key = self.key.export_key().decode("utf-8")
        self.public_key = self.key.publickey().export_key().decode("utf-8")

        # print(f"keys generated {self.private_key} and {self.public_key}")
    def generateLabel(self):
        return str(uuid.uuid4())

    def save_to_file(self, keys_file, label=None):
        
        key_data = self.load_existing(keys_file)
        label = label or self.generateLabel()

        # Add or update the key-value pair for the given label
        key_data[label] = {
            'private_key': self.private_key,
            'public_key': self.public_key
        }
        
        # Write the updated key_data back to the file
        with open(keys_file, 'w') as file:
            yaml.dump(key_data, file, default_flow_style=False)
        
        print(f"Keys saved to {keys_file}")


    def load_existing(self, keys_file):
        if os.path.exists(keys_file):
            try:
                with open(keys_file, "r") as save:
                    try:
                        return yaml.load(save, Loader=yaml.SafeLoader) or {}
                    except yaml.YAMLError as e:
                        raise ValueError(f"Error with the YAML file: {e}")
            except FileNotFoundError:
                return {}
        else:
            return {}



    def load_keys(self, keys_file, label = None):
        if not os.path.exists(keys_file):
                FileNotFoundError(f"file not found {keys_file}")


        with open (keys_file, "r") as read_file:
            keys = yaml.load(read_file, Loader=yaml.SafeLoader) or {}
            label = label or "default"
            if label not in keys:
                raise KeyError(f"Error keys not found {label} : {keys_file}")
            private_key = RSA.import_key(keys[label]["private_key"])
            public_key = RSA.import_key(keys[label]["public_key"])
            return private_key, public_key

        
    def encrypt_message(self, message, public_key):
        cipher = PKCS1_OAEP.new(public_key)
        encrypted = cipher.encrypt(message.encode())
        return base64.b64encode(encrypted).decode("utf-8")

    def decrypt_message(self, encrypted, private_key):
        cipher = PKCS1_OAEP.new(private_key)
        decrypt = cipher.decrypt(base64.b64decode(encrypted))
        return decrypt.decode("utf-8")


if __name__ == "__main__":
    rsa = RSAgen()
    label = rsa.generateLabel()

    rsa.save_to_file("keys_file.yaml",label=label)

    with open("label_file.yaml", "a") as label_file:
        label_file.write(label + "\n")

    with open("label_file.yaml", "r") as read_label:
        saved_label = read_label.read().strip()
    
    private_key, public_key = rsa.load_keys("keys_file.yaml", label=label)
    
    message = "this is a secret message hidden with RSA"

    encrypted_message = rsa.encrypt_message(message, public_key)
    print(f"message successfully encrypted {encrypted_message}")
    
    decrypted_message = rsa.decrypt_message(encrypted_message, private_key)
    print(f"message has been decrypted, it says {decrypted_message}")

    with open ("text_file.yaml", "a") as save_txt:
            save_txt.write(decrypted_message + "\n")

            
    
