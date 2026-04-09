import secrets
import bcrypt
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv
import random
import requests

load_dotenv()

# HASHING (Password Security)

def hash_password(plain_text_password: str) -> str:
    """
    Hashes a password using bcrypt with an automatically generated salt.
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_text_password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain_text_password: str, hashed_password: str) -> bool:
    """
    Verifies a plaintext password against the stored bcrypt hash.
    """
    return bcrypt.checkpw(plain_text_password.encode('utf-8'), hashed_password.encode('utf-8'))


# SYMMETRIC ENCRYPTION (Data at Rest)

STATIC_SECRET_KEY = b'vX9P-Q8mN_uG5F2T7jL4wR1eY3cK0bM8oH6aD5sS9A0=' 
cipher_suite = Fernet(STATIC_SECRET_KEY)

def encrypt_data(sensitive_data: str) -> str:
    """
    Encrypts data BEFORE saving it to the database (Encryption at Rest).
    """
    encrypted_text = cipher_suite.encrypt(sensitive_data.encode('utf-8'))
    return encrypted_text.decode('utf-8')

def decrypt_data(encrypted_data: str) -> str:
    """
    Decrypts data pulled from the database before sending it to the frontend.
    """
    decrypted_text = cipher_suite.decrypt(encrypted_data.encode('utf-8'))
    return decrypted_text.decode('utf-8')


# 3. SECURE PROTOCOLS (Secure Mail via Brevo API)

def generate_verification_token() -> str:
    """Generates a cryptographically secure random token for email links."""
    return secrets.token_urlsafe(32)

def send_real_secure_email(receiver_email: str, token: str):
    """Sends a real email securely over HTTP using the Brevo API."""
    api_key = os.getenv("BREVO_API_KEY")
    sender_email = os.getenv("GMAIL_ADDRESS")
    
    if not api_key or not sender_email:
        print(" Error: Missing BREVO_API_KEY or GMAIL_ADDRESS in Environment Variables.")
        return

    verification_link = f"https://vault-backend-api-szxu.onrender.com/verify/{token}"
    
    url = "https://api.brevo.com/v3/smtp/email"
    headers = {
        "accept": "application/json",
        "api-key": api_key,
        "content-type": "application/json"
    }
    payload = {
        "sender": {"name": "Secure Vault Support", "email": sender_email},
        "to": [{"email": receiver_email}],
        "subject": "Verify your Secure Bank Account",
        "htmlContent": f"<h3>Welcome to Secure Bank!</h3><p>Please click the secure link below to verify your identity:</p><p><a href='{verification_link}'>{verification_link}</a></p>"
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        print(f" Real API email securely sent to {receiver_email}!")
    except Exception as e:
        print(f" Failed to send API email: {e}")

def send_password_reset_email(receiver_email: str, token: str):
    """Sends a password reset email securely via the Brevo API."""
    api_key = os.getenv("BREVO_API_KEY")
    sender_email = os.getenv("GMAIL_ADDRESS")
    
    if not api_key or not sender_email:
        print("Missing API credentials.")
        return

    reset_link = f"https://vault-backend-api-szxu.onrender.com/reset-password-page/{token}"
    
    url = "https://api.brevo.com/v3/smtp/email"
    headers = {
        "accept": "application/json",
        "api-key": api_key,
        "content-type": "application/json"
    }
    payload = {
        "sender": {"name": "Secure Vault Security", "email": sender_email},
        "to": [{"email": receiver_email}],
        "subject": "Secure Bank - Password Reset Request",
        "htmlContent": f"<h3>Password Reset Request</h3><p>Please click the secure link below to create a new password:</p><p><a href='{reset_link}'>{reset_link}</a></p><p>If you did not request this, please ignore this email.</p>"
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        print(f"Password reset API email sent to {receiver_email}!")
    except Exception as e:
        print(f"Failed to send reset API email: {e}")

def generate_otp() -> str:
    """Generates a random 6-digit OTP code."""
    return str(random.randint(100000, 999999))

def send_transfer_otp_email(receiver_email: str, otp: str, amount: str, recipient: str):
    """Sends a 6-digit OTP to authorize a transfer via the Brevo API."""
    api_key = os.getenv("BREVO_API_KEY")
    sender_email = os.getenv("GMAIL_ADDRESS")
    
    if not api_key or not sender_email:
        print("Missing API credentials.")
        return

    url = "https://api.brevo.com/v3/smtp/email"
    headers = {
        "accept": "application/json",
        "api-key": api_key,
        "content-type": "application/json"
    }
    payload = {
        "sender": {"name": "Secure Vault Transfers", "email": sender_email},
        "to": [{"email": receiver_email}],
        "subject": f"Secure Bank - Transfer Authorization (OTP: {otp})",
        "htmlContent": f"<h3>Transfer Authorization Request</h3><p>You requested a transfer of <strong>${amount}</strong> to account <strong>{recipient}</strong>.</p><p>Your One-Time Password (OTP) is: <h2 style='color:blue;'>{otp}</h2></p><p>This code will expire in 5 minutes.</p>"
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        print(f"OTP API email sent to {receiver_email}!")
    except Exception as e:
        print(f"Failed to send OTP API email: {e}")