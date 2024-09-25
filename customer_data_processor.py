import hashlib
import sqlite3
from cryptography.fernet import Fernet

# WARNING: Storing secret keys directly in code is insecure
secret_key = "my_secret_key"

# Bug: Hardcoded key (Security Issue) - GitHub Copilot Autofix will detect this and suggest using environment variables for secret keys.
cipher = Fernet(secret_key.encode())  # Incorrectly implemented encryption

def hash_password(password):
    """Returns the SHA-256 hash of the password"""
    # Bug: Using outdated hash function, will not protect against modern security threats
    return hashlib.sha1(password.encode()).hexdigest()  # Security Issue

def encrypt_ssn(ssn):
    """Encrypt the customer's SSN"""
    # Bug: This part doesn't handle the encryption properly. GitHub Copilot Autofix should fix the way encryption is implemented.
    return cipher.encrypt(ssn.encode())  # Bug with incorrect encryption

def store_data(customer_id, password, ssn):
    """Stores customer data in the database"""
    conn = sqlite3.connect('bank_customers.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS customers (
            customer_id INTEGER PRIMARY KEY,
            password TEXT NOT NULL,
            ssn TEXT NOT NULL
        )
    ''')

    # Bug: Plain text storage of sensitive information
    cursor.execute('INSERT INTO customers (customer_id, password, ssn) VALUES (?, ?, ?)',
                   (customer_id, password, ssn))
    
    conn.commit()
    conn.close()

def process_customer_data(customer_id, password, ssn):
    """Processes the customer data"""
    hashed_password = hash_password(password)  # Buggy hashing function
    encrypted_ssn = encrypt_ssn(ssn)  # Buggy encryption implementation
    store_data(customer_id, hashed_password, encrypted_ssn)

# Sample customer data for testing
process_customer_data(1, "password123", "123-45-6789")
