from fastapi import FastAPI, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse
import sqlite3
import os
from contextlib import asynccontextmanager
import uvicorn # New: Import uvicorn

# --- Database Setup ---
DATABASE_NAME = "demo.db"

def get_db_connection():
    """Establishes and returns a database connection."""
    # *** CHANGE THIS LINE ***
    # Add check_same_thread=False to allow cross-thread usage (required for FastAPI with sqlite3)
    conn = sqlite3.connect(DATABASE_NAME, check_same_thread=False)
    conn.row_factory = sqlite3.Row # Allows accessing columns by name
    return conn

def init_db():
    """Initializes the database schema and populates with dummy data."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    # Insert some dummy data for testing
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ("admin", "secure_password_123"))
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ("john_doe", "johndoe123"))
    conn.commit()
    conn.close()

# --- Lifespan Event Handler ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handles application startup and shutdown events.
    Code before 'yield' runs on startup.
    Code after 'yield' runs on shutdown.
    """
    print("Application starting up...")
    init_db() # Run your database initialization logic here
    print(f"Database '{DATABASE_NAME}' initialized with dummy users.")
    yield # The application is now ready to receive requests
    print("Application shutting down...")
    # Optional: Add cleanup logic here if needed.

# --- Initialize FastAPI app with the lifespan handler ---
app = FastAPI(
    title="FastAPI SQL Injection Demo (CWE-89)",
    description="Illustrates SQL Injection (Vulnerable) vs. Secure Login (Parameterized Queries).",
    version="1.0.0",
    lifespan=lifespan # Pass the lifespan handler here
)

# --- Helper for database dependency injection ---
def get_db():
    conn = None
    try:
        conn = get_db_connection()
        yield conn
    finally:
        if conn:
            conn.close()

# --- Routes ---

@app.get("/", response_class=HTMLResponse)
async def read_root():
    """Provides a simple HTML interface to test login endpoints."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>FastAPI SQL Injection Demo</title>
        <style>
            body { font-family: sans-serif; margin: 20px; }
            form { margin-bottom: 30px; padding: 20px; border: 1px solid #ccc; border-radius: 8px; }
            input[type="text"], input[type="password"] { padding: 8px; margin: 5px 0; width: 200px; border-radius: 4px; border: 1px solid #ddd; }
            input[type="submit"] { padding: 10px 15px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
            input[type="submit"]:hover { background-color: #0056b3; }
            pre { background-color: #eee; padding: 10px; border-radius: 4px; overflow-x: auto; }
            h2 { color: #333; }
            .vulnerable { background-color: #ffe0e0; border-color: #ff0000; }
            .secure { background-color: #e0ffe0; border-color: #008000; }
        </style>
    </head>
    <body>
        <h1>FastAPI SQL Injection Demo</h1>

        <h2>1. Vulnerable Login Endpoint (`/login_vulnerable`)</h2>
        <p>This endpoint is vulnerable to SQL Injection. Try the following inputs:</p>
        <ul>
            <li><b>Legitimate:</b> Username: <code>john_doe</code>, Password: <code>johndoe123</code></li>
            <li><b>SQL Injection (Bypass admin password):</b>
                <br>Username: <code>admin</code>
                <br>Password: <code>' OR 1=1 --</code>
                <br>(The <code>--</code> comments out the rest of the query. SQLite supports it, as do many other SQL dialects)
            </li>
            <li><b>SQL Injection (Another bypass attempt):</b>
                <br>Username: <code>' OR '1'='1</code>
                <br>Password: <code>anything</code>
            </li>
        </ul>
        <form action="/login_vulnerable" method="post" class="vulnerable">
            <label for="vuln_username">Username:</label>
            <input type="text" id="vuln_username" name="username" value="admin"><br>
            <label for="vuln_password">Password:</label>
            <input type="password" id="vuln_password" name="password" value=""><br>
            <input type="submit" value="Login (Vulnerable)">
        </form>

        <h2>2. Secure Login Endpoint (`/login_secure`)</h2>
        <p>This endpoint uses parameterized queries to prevent SQL Injection. The same attack payloads will not work here.</p>
        <form action="/login_secure" method="post" class="secure">
            <label for="secure_username">Username:</label>
            <input type="text" id="secure_username" name="username" value="john_doe"><br>
            <label for="secure_password">Password:</label>
            <input type="password" id="secure_password" name="password" value="johndoe123"><br>
            <input type="submit" value="Login (Secure)">
        </form>

        <p>Check the console where you run Uvicorn for debug SQL queries.</p>
    </body>
    </html>
    """

@app.post("/login_vulnerable")
async def login_vulnerable(username: str = Form(...), password: str = Form(...), db: sqlite3.Connection = Depends(get_db)):
    """
    *** VULNERABLE ENDPOINT: SQL INJECTION (CWE-89) ***
    This endpoint is susceptible to SQL Injection because it concatenates
    user input directly into the SQL query string.
    """
    cursor = db.cursor()

    # !!! VULNERABLE CODE !!!
    # User input is directly interpolated into the SQL string.
    sql_query = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"\n[DEBUG - VULNERABLE] Executing SQL: {sql_query}")

    try:
        cursor.execute(sql_query)
        user = cursor.fetchone()
        if user:
            return {"message": f"Login SUCCESS for user: {user['username']}", "user_id": user['id']}
        else:
            raise HTTPException(status_code=401, detail="Invalid username or password.")
    except sqlite3.Error as e:
        print(f"[ERROR] Database error: {e}")
        raise HTTPException(status_code=500, detail=f"Database error during login: {e}")

@app.post("/login_secure")
async def login_secure(username: str = Form(...), password: str = Form(...), db: sqlite3.Connection = Depends(get_db)):
    """
    SECURE ENDPOINT: Prevents SQL Injection using parameterized queries.
    This is the recommended way to handle user input in SQL.
    """
    cursor = db.cursor()

    # SECURE CODE: Use placeholders (?) and pass parameters as a tuple.
    # The database driver handles the escaping, preventing injection.
    sql_query = "SELECT id, username FROM users WHERE username = ? AND password = ?"
    print(f"\n[DEBUG - SECURE] Executing SQL: {sql_query} with parameters ('{username}', '*****')")

    try:
        cursor.execute(sql_query, (username, password))
        user = cursor.fetchone()
        if user:
            return {"message": f"Login SUCCESS for user: {user['username']}", "user_id": user['id']}
        else:
            raise HTTPException(status_code=401, detail="Invalid username or password.")
    except sqlite3.Error as e:
        print(f"[ERROR] Database error: {e}")
        raise HTTPException(status_code=500, detail=f"Database error during login: {e}")


# --- Embed Uvicorn runner ---
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
    # Important:
    # - host="0.0.0.0" makes it accessible from your network (if firewall allows).
    #   Use host="127.0.0.1" for localhost only.
    # - reload=True is for development: it restarts the server on code changes.
    #   Remove reload=True for production deployments.