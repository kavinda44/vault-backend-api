import secrets
import bcrypt
from cryptography.fernet import Fernet
import smtplib
from email.message import EmailMessage
import os
from dotenv import load_dotenv
import random


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


# 3. SECURE PROTOCOLS (Secure Mail)


def generate_verification_token() -> str:
    """Generates a cryptographically secure random token for email links."""
    return secrets.token_urlsafe(32)

def send_real_secure_email(receiver_email: str, token: str):
    """
    Sends a real email securely over SMTPS using Gmail.
    """
    sender_email = os.getenv("GMAIL_ADDRESS")
    app_password = os.getenv("GMAIL_APP_PASSWORD")
    
    if not sender_email or not app_password:
        print(" Error: Missing Gmail credentials in .env file.")
        return

   
    msg = EmailMessage()
    msg['Subject'] = 'Verify your Secure Bank Account'
    msg['From'] = sender_email
    msg['To'] = receiver_email

    verification_link = f"http://127.0.0.1:8000/verify/{token}"
    msg.set_content(f"Welcome to Secure Bank!\n\nPlease click the secure link below to verify your identity:\n{verification_link}")

    try:
        
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(sender_email, app_password)
            smtp.send_message(msg)
        print(f" Real email securely sent to {receiver_email}!")
    except Exception as e:
        print(f" Failed to send email: {e}")

def send_password_reset_email(receiver_email: str, token: str):
    """Sends a real password reset email securely via Gmail."""
    sender_email = os.getenv("GMAIL_ADDRESS")
    app_password = os.getenv("GMAIL_APP_PASSWORD")
    
    if not sender_email or not app_password:
        print("Missing Gmail credentials.")
        return

    msg = EmailMessage()
    msg['Subject'] = 'Secure Bank - Password Reset Request'
    msg['From'] = sender_email
    msg['To'] = receiver_email

    
    reset_link = f"http://127.0.0.1:8000/reset-password-page/{token}"
    msg.set_content(f"We received a request to reset your password.\n\nPlease click the secure link below to create a new password:\n{reset_link}\n\nIf you did not request this, please ignore this email.")

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(sender_email, app_password)
            smtp.send_message(msg)
        print(f"Password reset email sent to {receiver_email}!")
    except Exception as e:
        print(f"Failed to send reset email: {e}")



def generate_otp() -> str:
    """Generates a random 6-digit OTP code."""
    return str(random.randint(100000, 999999))

def send_transfer_otp_email(receiver_email: str, otp: str, amount: str, recipient: str):
    """Sends a 6-digit OTP to authorize a transfer."""
    sender_email = os.getenv("GMAIL_ADDRESS")
    app_password = os.getenv("GMAIL_APP_PASSWORD")
    
    if not sender_email or not app_password:
        print("Missing Gmail credentials.")
        return

    msg = EmailMessage()
    msg['Subject'] = f'Secure Bank - Transfer Authorization (OTP: {otp})'
    msg['From'] = sender_email
    msg['To'] = receiver_email

    msg.set_content(
        f"You requested a transfer of ${amount} to account {recipient}.\n\n"
        f"Your One-Time Password (OTP) is: {otp}\n\n"
        f"This code will expire in 5 minutes. If you did not request this, please contact support immediately."
    )

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(sender_email, app_password)
            smtp.send_message(msg)
        print(f"OTP email sent to {receiver_email}!")
    except Exception as e:
        print(f"Failed to send OTP email: {e}")