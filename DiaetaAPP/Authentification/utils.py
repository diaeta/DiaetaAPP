# utils.py
from cryptography.fernet import Fernet
import os

# Function to get Fernet object for encryption/decryption
def get_fernet():
    # Retrieve key from environment variable
    key = os.getenv('FERNET_KEY')
    return Fernet(key)
