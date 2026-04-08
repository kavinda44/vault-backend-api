from fastapi import FastAPI, HTTPException, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import security_helpers  
import database  
from fastapi.responses import HTMLResponse
import time
import random
import sqlite3 

# Initialize the API and Database
app = FastAPI(title="Secure Banking Prototype API")
database.init_db() 

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Intrusion Prevention System (IPS) Memory 
FAILED_LOGIN_ATTEMPTS = {} 
MAX_RETRIES = 3
LOCKOUT_TIME = 60 

# OTP Transfer Memory 
PENDING_TRANSFERS = {} 

# API Data Models
class TransferRequest(BaseModel):
    username: str
    recipient_account: str
    amount: str 

class VerifyTransferRequest(BaseModel):
    username: str
    otp: str

class RegisterRequest(BaseModel):
    username: str
    email: str
    nic: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class ForgotPasswordRequest(BaseModel):
    email: str

# --- UPDATED: Profile Model (No Email, Optional Passwords) ---
class ProfileUpdateRequest(BaseModel):
    current_username: str
    new_username: str
    current_password: str = "" # Optional
    new_password: str = ""     # Optional


# API Endpoints

@app.post("/register")
def register(request: RegisterRequest):
    hashed_pw = security_helpers.hash_password(request.password)
    verification_token = security_helpers.generate_verification_token()
    
    # 1. Generate a random 6-digit Account Number
    random_account = f"ACC-{random.randint(100000, 999999)}"
    
    # 2. Generate a random initial balance between $1,000 and $25,000
    random_balance = round(random.uniform(1000.0, 25000.0), 2)
    
    success = database.create_user(
        request.username, request.email, request.nic, random_account, random_balance, hashed_pw, verification_token
    )
    
    if not success:
        raise HTTPException(status_code=400, detail="Username, Email, or NIC already exists")
    
    security_helpers.send_real_secure_email(request.email, verification_token)
    return {"message": "Registration successful. Please check your email to verify your account."}

@app.get("/verify/{token}")
def verify_email(token: str):

    if database.verify_user_in_db(token):
       
        from fastapi.responses import HTMLResponse
        return HTMLResponse("<h2> Email Verified Successfully! You can now close this tab and log in.</h2>")
    
    raise HTTPException(status_code=400, detail="Invalid or expired verification token.")

@app.post("/login")
def login(request: LoginRequest, fastapi_req: Request):
    client_ip = fastapi_req.client.host
    current_time = time.time()

    if client_ip in FAILED_LOGIN_ATTEMPTS:
        attempts, lockout_expiry = FAILED_LOGIN_ATTEMPTS[client_ip]
        if current_time < lockout_expiry:
            time_left = int(lockout_expiry - current_time)
            raise HTTPException(
                status_code=429, 
                detail=f"IPS Block: Too many failed attempts. Try again in {time_left}s."
            )
        elif current_time > lockout_expiry and attempts >= MAX_RETRIES:
            FAILED_LOGIN_ATTEMPTS[client_ip] = [0, 0]

    user = database.get_user(request.username)
    
    if not user or not security_helpers.verify_password(request.password, user["password_hash"]):
        
        # IPS TRACKING: Record the failed attempt
        if client_ip not in FAILED_LOGIN_ATTEMPTS:
            FAILED_LOGIN_ATTEMPTS[client_ip] = [1, 0]
        else:
            FAILED_LOGIN_ATTEMPTS[client_ip][0] += 1
            
        attempts_made = FAILED_LOGIN_ATTEMPTS[client_ip][0]
            
        # IPS CHECK 2: Did they just hit the maximum limit
        if attempts_made >= MAX_RETRIES:
            FAILED_LOGIN_ATTEMPTS[client_ip][1] = current_time + LOCKOUT_TIME
            raise HTTPException(
                status_code=429, 
                detail="IPS Triggered: Brute-force detected. IP locked out for 60 seconds."
            )
        
        raise HTTPException(
            status_code=401, 
            detail=f"Invalid credentials. Attempts remaining: {MAX_RETRIES - attempts_made}"
        )
    
    # Block login if email isn't verified
    if not user["is_verified"]:
        raise HTTPException(status_code=403, detail="Please verify your email before logging in.")
    
    if client_ip in FAILED_LOGIN_ATTEMPTS:
        FAILED_LOGIN_ATTEMPTS.pop(client_ip)

    return {
        "message": "Login successful",
        "username": user["username"],
        "account_number": user["account_number"],
        "balance": user["balance"],
        "email": user.get("email", "") 
    }

# --- UPDATED: REAL PROFILE UPDATE ROUTE ---
@app.post("/user/update")
def update_profile(req: ProfileUpdateRequest):
    conn = sqlite3.connect("secure_bank.db")
    cursor = conn.cursor()
    
    try:
        # Step A: Prevent changing to an already-taken username
        if req.new_username != req.current_username:
            cursor.execute("SELECT username FROM users WHERE username = ?", (req.new_username,))
            if cursor.fetchone():
                raise HTTPException(status_code=400, detail="That username is already taken by another account.")
                
        # Step B: If they typed a NEW password, we MUST verify the old one
        if req.new_password:
            if not req.current_password:
                raise HTTPException(status_code=400, detail="Current password is required to set a new password.")
                
            cursor.execute("SELECT password_hash FROM users WHERE username = ?", (req.current_username,))
            row = cursor.fetchone()
            
            if not row or not security_helpers.verify_password(req.current_password, row[0]):
                raise HTTPException(status_code=401, detail="Incorrect current password. Changes denied.")
                
            # Hash the new password and update both name and password (No email)
            new_hash = security_helpers.hash_password(req.new_password)
            cursor.execute("""
                UPDATE users 
                SET username = ?, password_hash = ?
                WHERE username = ?
            """, (req.new_username, new_hash, req.current_username))
            
        else:
            # Step C: If no new password was typed, JUST update the username (No email)
            cursor.execute("""
                UPDATE users 
                SET username = ?
                WHERE username = ?
            """, (req.new_username, req.current_username))
            
        conn.commit()
        return {"message": "Database profile updated successfully!"}
        
    finally:
        conn.close()


@app.post("/transfer/request")
def request_transfer(request: TransferRequest):
    """Step 1: Validates funds/accounts, generates OTP, and emails it."""
    # VALIDATION 1: Does the recipient account exist?
    if not database.get_user_by_account(request.recipient_account):
        raise HTTPException(status_code=404, detail="Invalid Recipient Account Number.")

    # VALIDATION 2: Does the sender have enough money?
    sender_data = database.get_user(request.username)
    transfer_amount = float(request.amount)
    
    if sender_data["balance"] < transfer_amount:
        raise HTTPException(status_code=400, detail="Insufficient funds.")

    otp = security_helpers.generate_otp()
    expiry = time.time() + 300 

    email = database.get_user_email(request.username)
    otp = security_helpers.generate_otp()
    PENDING_TRANSFERS[request.username] = {
        "otp": otp,
        "recipient": request.recipient_account,
        "amount": transfer_amount,
        "expiry": time.time() + 300
    }
    security_helpers.send_transfer_otp_email(email, otp, str(transfer_amount), request.recipient_account)
    return {"message": "OTP sent securely to your registered email."}

@app.post("/transfer/verify")
def verify_transfer(request: VerifyTransferRequest):
    
    pending = PENDING_TRANSFERS.get(request.username)
    if not pending:
        raise HTTPException(status_code=400, detail="No pending transfer found.")

    if time.time() > pending["expiry"]:
        del PENDING_TRANSFERS[request.username]
        raise HTTPException(status_code=400, detail="OTP has expired.")

    if request.otp != pending["otp"]:
        raise HTTPException(status_code=401, detail="Invalid OTP code.")

    
    encrypted_amount = security_helpers.encrypt_data(str(pending["amount"]))
    
    # NEW: Actually move the money in the database
    success = database.execute_secure_transfer(
        request.username, pending["recipient"], pending["amount"], encrypted_amount
    )

    if not success:
        raise HTTPException(status_code=500, detail="Database transaction failed.")

    del PENDING_TRANSFERS[request.username]

    return {
        "status": "Success",
        "message": "Transfer authorized. Funds have been deducted.",
        "raw_encrypted_payload": encrypted_amount 
    }

@app.post("/forgot-password")
def forgot_password(request: ForgotPasswordRequest):
    # Generate a secure token
    token = security_helpers.generate_verification_token()
    
    # If the email exists in the DB, save the token and send the email
    if database.set_reset_token(request.email, token):
        security_helpers.send_password_reset_email(request.email, token)
        
   
    return {"message": "If an account exists with that email, a reset link has been sent."}


@app.get("/reset-password-page/{token}", response_class=HTMLResponse)
def reset_password_page(token: str):
    html_content = f"""
    <html>
        <body style="font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #e2e2e2;">
            <div style="background: white; padding: 40px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.2); width: 300px; text-align: center;">
                <h2 style="color: #333;">Create New Password</h2>
                <form action="/reset-password-confirm" method="post" style="display: flex; flex-direction: column; gap: 15px; margin-top: 20px;">
                    <input type="hidden" name="token" value="{token}">
                    <input type="password" name="new_password" placeholder="Enter new password" required style="padding: 10px; border: 1px solid #ccc; border-radius: 6px;">
                    <button type="submit" style="padding: 10px; background-color: #512da8; color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: bold;">Securely Reset Password</button>
                </form>
            </div>
        </body>
    </html>
    """
    return html_content


@app.post("/reset-password-confirm")
def reset_password_confirm(token: str = Form(...), new_password: str = Form(...)):
    
    hashed_pw = security_helpers.hash_password(new_password)
    
    if database.update_password_with_token(token, hashed_pw):
        return HTMLResponse("<h2 style='text-align:center; margin-top:50px; font-family:sans-serif;'> Password updated securely! You can safely close this tab and log in to the website.</h2>")
    
    raise HTTPException(status_code=400, detail="Invalid or expired reset token.")