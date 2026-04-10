import secrets
import bcrypt
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv
import random
import resend

load_dotenv()

# Set up Resend API Key
resend.api_key = os.getenv("RESEND_API_KEY")

# HASHING (Password Security)
def hash_password(plain_text_password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_text_password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain_text_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_text_password.encode('utf-8'), hashed_password.encode('utf-8'))

# SYMMETRIC ENCRYPTION (Data at Rest)
STATIC_SECRET_KEY = b'vX9P-Q8mN_uG5F2T7jL4wR1eY3cK0bM8oH6aD5sS9A0=' 
cipher_suite = Fernet(STATIC_SECRET_KEY)

def encrypt_data(sensitive_data: str) -> str:
    encrypted_text = cipher_suite.encrypt(sensitive_data.encode('utf-8'))
    return encrypted_text.decode('utf-8')

def decrypt_data(encrypted_data: str) -> str:
    decrypted_text = cipher_suite.decrypt(encrypted_data.encode('utf-8'))
    return decrypted_text.decode('utf-8')

# SECURE PROTOCOLS (Secure Mail via Resend API)
def generate_verification_token() -> str:
    return secrets.token_urlsafe(32)

def send_real_secure_email(receiver_email: str, token: str):
    """Sends a verification email securely via Resend."""
    if not resend.api_key:
        print(" Error: Missing RESEND_API_KEY in Environment Variables.")
        return

    verification_link = f"https://vault-backend-api-szxu.onrender.com/verify/{token}"
    
    html_content = f"""
        <div style='background:#f4f4f5; padding:20px; font-family:sans-serif;'>
            <p style='color:red; font-weight:bold;'>⚠️ TEST EMAIL FOR UNIVERSITY PROJECT. NO REAL BANKING DATA INVOLVED.</p>
            <h3>Welcome to the simulated Secure Bank App!</h3>
            <p>Please click the secure link below to verify your test account:</p>
            <p><a href='{verification_link}'>{verification_link}</a></p>
        </div>
    """

    try:
        # Note: 'onboarding@resend.dev' is the mandatory testing sender until you verify a custom domain
        resend.Emails.send({
            "from": "University Security Project <onboarding@resend.dev>",
            "to": receiver_email,
            "subject": "[TEST] Verify Account - University Project",
            "html": html_content
        })
        print(f" Resend API email successfully sent to {receiver_email}!")
    except Exception as e:
        print(f" Failed to send Resend email: {e}")

def send_password_reset_email(receiver_email: str, token: str):
    """Sends a password reset email securely via Resend."""
    if not resend.api_key:
        return

    reset_link = f"https://vault-backend-api-szxu.onrender.com/reset-password-page/{token}"
    
    html_content = f"""
        <div style='background:#f4f4f5; padding:20px; font-family:sans-serif;'>
            <p style='color:red; font-weight:bold;'>⚠️ TEST EMAIL FOR UNIVERSITY PROJECT. NO REAL BANKING DATA INVOLVED.</p>
            <h3>Simulated Password Reset Request</h3>
            <p>Please click the secure link below to create a new test password:</p>
            <p><a href='{reset_link}'>{reset_link}</a></p>
        </div>
    """

    try:
        resend.Emails.send({
            "from": "University Security Project <onboarding@resend.dev>",
            "to": receiver_email,
            "subject": "[TEST] Password Reset - University Security Project",
            "html": html_content
        })
        print(f"Password reset email sent to {receiver_email}!")
    except Exception as e:
        print(f"Failed to send reset email: {e}")

def generate_otp() -> str:
    return str(random.randint(100000, 999999))

def send_transfer_otp_email(receiver_email: str, otp: str, amount: str, recipient: str):
    """Sends a 6-digit OTP to authorize a transfer via Resend."""
    if not resend.api_key:
        return

    html_content = f"""
        <div style='background:#f4f4f5; padding:20px; font-family:sans-serif;'>
            <p style='color:red; font-weight:bold;'>⚠️ TEST EMAIL FOR UNIVERSITY SECURITY PROJECT. NO REAL BANKING DATA INVOLVED.</p>
            <h3>Simulated Transfer Authorization</h3>
            <p>You requested a test transfer of <strong>${amount}</strong> to account <strong>{recipient}</strong>.</p>
            <p>Your test OTP is: <h2 style='color:blue;'>{otp}</h2></p>
            <p>This code will expire in 5 minutes.</p>
        </div>
    """

    try:
        resend.Emails.send({
            "from": "University Security Project <onboarding@resend.dev>",
            "to": receiver_email,
            "subject": f"[TEST] Transfer OTP: {otp} - University Project",
            "html": html_content
        })
        print(f"OTP email sent to {receiver_email}!")
    except Exception as e:
        print(f"Failed to send OTP email: {e}")