"""MySQL users table + salted hashing (no chat storage)."""

import pymysql
import os
import sys
import hashlib
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get database connection details from environment
DB_HOST = os.getenv("MYSQL_HOST", "127.0.0.1")
DB_USER = os.getenv("MYSQL_USER")
DB_PASSWORD = os.getenv("MYSQL_PASSWORD")
DB_NAME = os.getenv("MYSQL_DATABASE")

def get_db_connection():
    """Establishes a connection to the MySQL database."""
    try:
        conn = pymysql.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            cursorclass=pymysql.cursors.DictCursor
        )
        return conn
    except pymysql.MySQLError as e:
        print(f"Error connecting to MySQL: {e}")
        sys.exit(1) # Exit if we can't connect

def init_db():
    """Creates the users table if it doesn't exist."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # SQL command to create the table, as specified in the PDF
            create_table_query = """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) NOT NULL UNIQUE,
                username VARCHAR(255) NOT NULL UNIQUE,
                salt VARBINARY(16) NOT NULL,
                pwd_hash CHAR(64) NOT NULL
            );
            """
            cursor.execute(create_table_query)
        conn.commit()
        print("Database initialized successfully. 'users' table created.")
    except pymysql.MySQLError as e:
        print(f"Error initializing database: {e}")
    finally:
        conn.close()

# --- Functions to be implemented later ---

def register_user(email, username, password):
    """(To be implemented in Step 2A)"""
    conn = get_db_connection()
    try:
        # 1. Generate a 16-byte random salt
        salt = os.urandom(16)
        
        # 2. Compute the salted password hash
        pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()

        # 3. Store in the database
        with conn.cursor() as cursor:
            sql = "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)"
            cursor.execute(sql, (email, username, salt, pwd_hash))
        conn.commit()
        print(f"Successfully registered user: {username}")
        return True
    except pymysql.MySQLError as e:
        print(f"Error registering user: {e}")
        return False
    finally:
        conn.close()


def get_user_for_login(email):
    """(To be implemented in Step 2A)"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            # Select the salt and hash for the given email
            sql = "SELECT salt, pwd_hash FROM users WHERE email = %s"
            cursor.execute(sql, (email,))
            result = cursor.fetchone()
            return result  # This will be a dictionary {'salt': ..., 'pwd_hash': ...} or None
    except pymysql.MySQLError as e:
        print(f"Error fetching user: {e}")
        return None
    finally:
        conn.close()


# This makes the --init flag work
if __name__ == "__main__":
    # Check if the script was called with the --init argument
    if len(sys.argv) > 1 and sys.argv[1] == '--init':
        init_db()
    else:
        print("This script is meant to be run with --init to set up the database.")
        print("Or, it can be imported as a module.")