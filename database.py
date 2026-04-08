import sqlite3

DB_NAME = "secure_bank.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # UPDATED: Added nic, account_number, and balance
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            nic TEXT UNIQUE NOT NULL,
            account_number TEXT UNIQUE NOT NULL,
            balance REAL NOT NULL,
            password_hash TEXT NOT NULL,
            is_verified BOOLEAN NOT NULL DEFAULT 0,
            verification_token TEXT,
            reset_token TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_account TEXT NOT NULL,
            recipient_account TEXT NOT NULL,
            encrypted_amount TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()
    print("Database initialized successfully with Core Banking features.")

def create_user(username: str, email: str, nic: str, account_number: str, initial_balance: float, password_hash: str, token: str):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, email, nic, account_number, balance, password_hash, verification_token) VALUES (?, ?, ?, ?, ?, ?, ?)", 
            (username, email, nic, account_number, initial_balance, password_hash, token)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False 
    finally:
        conn.close()

def get_user(username: str):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT username, password_hash, is_verified, account_number, balance FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return {
            "username": user[0], 
            "password_hash": user[1], 
            "is_verified": bool(user[2]),
            "account_number": user[3],
            "balance": user[4]
        }
    return None

def get_user_email(username: str):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT email FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user[0] if user else None

def get_user_by_account(account_number: str):
    """Checks if a recipient account exists."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE account_number = ?", (account_number,))
    user = cursor.fetchone()
    conn.close()
    return True if user else False

def verify_user_in_db(token: str):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE verification_token = ?", (token,))
    user = cursor.fetchone()
    if user:
        cursor.execute("UPDATE users SET is_verified = 1, verification_token = NULL WHERE id = ?", (user[0],))
        conn.commit()
        conn.close()
        return True
    conn.close()
    return False

def execute_secure_transfer(sender_username: str, recipient_account: str, amount: float, encrypted_amount: str):
    """Moves money safely and logs the encrypted payload."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        # Get sender's account number
        cursor.execute("SELECT account_number FROM users WHERE username = ?", (sender_username,))
        sender_account = cursor.fetchone()[0]

        # Deduct from Sender
        cursor.execute("UPDATE users SET balance = balance - ? WHERE username = ?", (amount, sender_username))
        
        # Add to Recipient
        cursor.execute("UPDATE users SET balance = balance + ? WHERE account_number = ?", (amount, recipient_account))

        # Save Encrypted Log
        cursor.execute("INSERT INTO transactions (sender_account, recipient_account, encrypted_amount) VALUES (?, ?, ?)", 
                       (sender_account, recipient_account, encrypted_amount))
        
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        print("Transfer Error:", e)
        return False
    finally:
        conn.close()
        

def set_reset_token(email: str, token: str) -> bool:
    """Saves a password reset token for a specific user."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET reset_token = ? WHERE email = ?", (token, email))
    rows_updated = cursor.rowcount
    conn.commit()
    conn.close()
    return rows_updated > 0

def update_password_with_token(token: str, new_password_hash: str) -> bool:
    """Verifies the reset token, updates the password, and clears the token."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute("UPDATE users SET password_hash = ?, reset_token = NULL WHERE reset_token = ?", 
                   (new_password_hash, token))
    rows_updated = cursor.rowcount
    conn.commit()
    conn.close()
    return rows_updated > 0

def get_user_email(username: str):
    """Fetches the user's email address for OTP delivery."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT email FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user[0] if user else None