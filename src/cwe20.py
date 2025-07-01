#!/usr/bin/env python3
"""
FastAPI CWE-20 Demonstration
Educational example showing vulnerable and secure endpoints
"""

from fastapi import FastAPI, HTTPException, Query, Path
from pydantic import BaseModel, validator, Field
from typing import Optional, List
import sqlite3
import os
import re
import tempfile
from pathlib import Path as PathLib
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="CWE-20 Demonstration API",
    description="Educational API showing input validation vulnerabilities and fixes",
    version="1.0.0",
    lifespan=lifespan
)

# Initialize in-memory database for demonstration
def init_db():
    """Initialize sample database"""
    conn = sqlite3.connect('demo.db')
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    # Insert sample data
    cursor.execute("DELETE FROM users")  # Clear existing data
    sample_users = [
        (1, 'alice', 'alice@example.com', 'admin'),
        (2, 'bob', 'bob@example.com', 'user'),
        (3, 'charlie', 'charlie@example.com', 'user'),
    ]
    
    cursor.executemany(
        "INSERT INTO users (id, username, email, role) VALUES (?, ?, ?, ?)",
        sample_users
    )
    
    conn.commit()
    conn.close()

# Initialize database and files on startup using lifespan
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    # Create sample files for file reading demo
    os.makedirs("safe_files", exist_ok=True)
    with open("safe_files/public.txt", "w") as f:
        f.write("This is a public file that can be safely accessed.")
    
    with open("secret.txt", "w") as f:
        f.write("This is a secret file that should not be accessible!")
    
    yield
    # Shutdown (cleanup if needed)
    pass

# =============================================================================
# VULNERABLE ENDPOINTS (CWE-20)
# =============================================================================

@app.get("/vulnerable/user/{user_id}")
async def get_user_vulnerable(user_id: str):
    """
    VULNERABLE ENDPOINT - SQL Injection (CWE-20)
    
    This endpoint is vulnerable to SQL injection because it directly 
    concatenates user input into SQL queries without validation.
    
    Try: /vulnerable/user/1' OR '1'='1
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # VULNERABILITY: Direct string concatenation - SQL Injection
        query = f"SELECT * FROM users WHERE id = '{user_id}'"
        logger.warning(f"Executing vulnerable query: {query}")
        
        cursor.execute(query)
        result = cursor.fetchall()
        conn.close()
        
        if result:
            return {
                "message": "User found",
                "data": result,
                "query_executed": query  # Never expose this in production!
            }
        else:
            return {"message": "No user found", "query_executed": query}
            
    except Exception as e:
        return {"error": str(e), "query_executed": query}


@app.get("/vulnerable/file")
async def read_file_vulnerable(filename: str = Query(..., description="Filename to read")):
    """
    VULNERABLE ENDPOINT - Path Traversal (CWE-20)
    
    This endpoint allows reading arbitrary files from the server
    because it doesn't validate the file path.
    
    Try: /vulnerable/file?filename=../secret.txt
    Try: /vulnerable/file?filename=../../etc/passwd
    """
    try:
        # VULNERABILITY: No path validation - Path Traversal
        logger.warning(f"Attempting to read file: {filename}")
        
        with open(filename, 'r') as f:
            content = f.read()
        
        return {
            "message": "File read successfully",
            "filename": filename,
            "content": content
        }
        
    except FileNotFoundError:
        return {"error": f"File not found: {filename}"}
    except Exception as e:
        return {"error": str(e)}


@app.get("/vulnerable/search")
async def search_users_vulnerable(
    query: str = Query(..., description="Search query"),
    limit: str = Query("10", description="Number of results")
):
    """
    VULNERABLE ENDPOINT - Multiple Input Validation Issues (CWE-20)
    
    1. SQL Injection in search query
    2. No validation of limit parameter
    3. Potential integer overflow
    
    Try: /vulnerable/search?query='; DROP TABLE users; --&limit=abc
    Try: /vulnerable/search?query=test&limit=999999999999999999999
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # VULNERABILITY 1: SQL Injection in LIKE clause
        sql_query = f"SELECT * FROM users WHERE username LIKE '%{query}%'"
        
        # VULNERABILITY 2: No validation of limit parameter
        try:
            limit_int = int(limit)  # Could cause ValueError
            sql_query += f" LIMIT {limit_int}"  # Could cause integer issues
        except ValueError:
            # Even error handling is vulnerable - exposing internal info
            return {"error": f"Invalid limit parameter: {limit}"}
        
        logger.warning(f"Executing vulnerable search: {sql_query}")
        cursor.execute(sql_query)
        results = cursor.fetchall()
        conn.close()
        
        return {
            "message": f"Found {len(results)} users",
            "query": query,
            "limit": limit,
            "results": results,
            "sql_executed": sql_query  # Never expose in production!
        }
        
    except Exception as e:
        return {"error": str(e), "sql_executed": sql_query}


# =============================================================================
# SECURE ENDPOINTS (Proper Input Validation)
# =============================================================================

class UserResponse(BaseModel):
    """Response model for user data"""
    id: int
    username: str
    email: str
    role: str

@app.get("/secure/user/{user_id}", response_model=dict)
async def get_user_secure(user_id: int = Path(..., ge=1, le=999999, description="User ID")):
    """
    SECURE ENDPOINT - Proper Input Validation
    
    - Uses path parameter with automatic type conversion
    - Validates range (ge=1, le=999999)
    - Uses parameterized queries
    - Proper error handling without information disclosure
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # SECURE: Parameterized query prevents SQL injection
        cursor.execute("SELECT id, username, email, role FROM users WHERE id = ?", (user_id,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            user_data = {
                "id": result[0],
                "username": result[1], 
                "email": result[2],
                "role": result[3]
            }
            return {
                "message": "User found",
                "data": user_data
            }
        else:
            raise HTTPException(status_code=404, detail="User not found")
            
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


@app.get("/secure/file")
async def read_file_secure(filename: str = Query(..., min_length=1, max_length=100, pattern=r'^[a-zA-Z0-9._-]+
    """
    SECURE ENDPOINT - Proper Path Validation
    
    - Validates filename format with regex
    - Restricts access to safe directory only
    - Prevents path traversal attacks
    - Proper error handling
    """
    try:
        # Define safe directory
        SAFE_DIR = PathLib("safe_files").resolve()
        
        # Validate filename doesn't contain path separators
        if '/' in filename or '\\' in filename:
            raise HTTPException(status_code=400, detail="Invalid filename: path separators not allowed")
        
        # Construct and validate file path
        file_path = SAFE_DIR / filename
        resolved_path = file_path.resolve()
        
        # Ensure the resolved path is within the safe directory
        if not str(resolved_path).startswith(str(SAFE_DIR)):
            raise HTTPException(status_code=403, detail="Access denied: path outside safe directory")
        
        # Check if file exists and is actually a file
        if not resolved_path.exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        if not resolved_path.is_file():
            raise HTTPException(status_code=400, detail="Path is not a file")
        
        # Read file content
        with open(resolved_path, 'r') as f:
            content = f.read()
        
        return {
            "message": "File read successfully",
            "filename": filename,
            "content": content
        }
        
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")


class SearchRequest(BaseModel):
    """Request model with validation for search endpoint"""
    query: str = Field(..., min_length=1, max_length=100, pattern=r'^[a-zA-Z0-9\s._-]+

@app.post("/secure/search")
async def search_users_secure(search_request: SearchRequest):
    """
    SECURE ENDPOINT - Comprehensive Input Validation
    
    - Uses Pydantic model for automatic validation
    - Parameterized queries prevent SQL injection
    - Proper range validation for limit
    - Regex validation for search query
    - Structured error responses
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # SECURE: Parameterized query with LIKE
        search_pattern = f"%{search_request.query}%"
        cursor.execute(
            "SELECT id, username, email, role FROM users WHERE username LIKE ? LIMIT ?",
            (search_pattern, search_request.limit)
        )
        
        results = cursor.fetchall()
        conn.close()
        
        # Format results
        users = []
        for row in results:
            users.append({
                "id": row[0],
                "username": row[1],
                "email": row[2], 
                "role": row[3]
            })
        
        return {
            "message": f"Found {len(users)} users",
            "total_results": len(users),
            "users": users
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# ADDITIONAL SECURE VALIDATION EXAMPLES
# =============================================================================

class CreateUserRequest(BaseModel):
    """Comprehensive input validation for user creation"""
    username: str = Field(..., min_length=3, max_length=50, pattern=r'^[a-zA-Z0-9_]+
    
    @validator('email')
    def validate_email_domain(cls, v):
        """Additional custom validation for email domain"""
        if v.endswith('.test') or v.endswith('.invalid'):
            raise ValueError('Invalid email domain')
        return v.lower()
    
    @validator('username')
    def validate_username_reserved(cls, v):
        """Check for reserved usernames"""
        reserved = ['admin', 'root', 'system', 'null', 'undefined']
        if v.lower() in reserved:
            raise ValueError('Username is reserved')
        return v

@app.post("/secure/user")
async def create_user_secure(user_request: CreateUserRequest):
    """
    SECURE ENDPOINT - Advanced Input Validation
    
    - Comprehensive Pydantic validation
    - Custom validators for business logic
    - SQL injection prevention
    - Proper error handling
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (user_request.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Username already exists")
        
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (user_request.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Email already exists")
        
        # Insert new user
        cursor.execute(
            "INSERT INTO users (username, email, role) VALUES (?, ?, ?)",
            (user_request.username, user_request.email, user_request.role)
        )
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return {
            "message": "User created successfully",
            "user_id": user_id,
            "username": user_request.username
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# DOCUMENTATION ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
    """API documentation and vulnerability demonstration guide"""
    return {
        "message": "CWE-20 Input Validation Demonstration API",
        "vulnerable_endpoints": {
            "GET /vulnerable/user/{user_id}": "SQL Injection vulnerability",
            "GET /vulnerable/file?filename=": "Path traversal vulnerability", 
            "GET /vulnerable/search?query=&limit=": "Multiple validation issues"
        },
        "secure_endpoints": {
            "GET /secure/user/{user_id}": "Proper parameter validation",
            "GET /secure/file?filename=": "Secure file access",
            "POST /secure/search": "Validated search with Pydantic",
            "POST /secure/user": "Comprehensive user creation validation"
        },
        "test_payloads": {
            "sql_injection": "1' OR '1'='1",
            "path_traversal": "../secret.txt",
            "command_injection": "test; rm -rf /",
            "xss": "<script>alert('xss')</script>"
        },
        "security_features": [
            "Parameterized queries",
            "Path validation and sanitization", 
            "Input type and range validation",
            "Regex pattern matching",
            "Custom business logic validation",
            "Proper error handling"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, debug=True)
)):
    """
    SECURE ENDPOINT - Proper Path Validation
    
    - Validates filename format with regex
    - Restricts access to safe directory only
    - Prevents path traversal attacks
    - Proper error handling
    """
    try:
        # Define safe directory
        SAFE_DIR = PathLib("safe_files").resolve()
        
        # Validate filename doesn't contain path separators
        if '/' in filename or '\\' in filename:
            raise HTTPException(status_code=400, detail="Invalid filename: path separators not allowed")
        
        # Construct and validate file path
        file_path = SAFE_DIR / filename
        resolved_path = file_path.resolve()
        
        # Ensure the resolved path is within the safe directory
        if not str(resolved_path).startswith(str(SAFE_DIR)):
            raise HTTPException(status_code=403, detail="Access denied: path outside safe directory")
        
        # Check if file exists and is actually a file
        if not resolved_path.exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        if not resolved_path.is_file():
            raise HTTPException(status_code=400, detail="Path is not a file")
        
        # Read file content
        with open(resolved_path, 'r') as f:
            content = f.read()
        
        return {
            "message": "File read successfully",
            "filename": filename,
            "content": content
        }
        
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")


class SearchRequest(BaseModel):
    """Request model with validation for search endpoint"""
    query: str = Field(..., min_length=1, max_length=100, regex=r'^[a-zA-Z0-9\s._-]+$')
    limit: int = Field(10, ge=1, le=100, description="Number of results (1-100)")

@app.post("/secure/search")
async def search_users_secure(search_request: SearchRequest):
    """
    SECURE ENDPOINT - Comprehensive Input Validation
    
    - Uses Pydantic model for automatic validation
    - Parameterized queries prevent SQL injection
    - Proper range validation for limit
    - Regex validation for search query
    - Structured error responses
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # SECURE: Parameterized query with LIKE
        search_pattern = f"%{search_request.query}%"
        cursor.execute(
            "SELECT id, username, email, role FROM users WHERE username LIKE ? LIMIT ?",
            (search_pattern, search_request.limit)
        )
        
        results = cursor.fetchall()
        conn.close()
        
        # Format results
        users = []
        for row in results:
            users.append({
                "id": row[0],
                "username": row[1],
                "email": row[2], 
                "role": row[3]
            })
        
        return {
            "message": f"Found {len(users)} users",
            "total_results": len(users),
            "users": users
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# ADDITIONAL SECURE VALIDATION EXAMPLES
# =============================================================================

class CreateUserRequest(BaseModel):
    """Comprehensive input validation for user creation"""
    username: str = Field(..., min_length=3, max_length=50, regex=r'^[a-zA-Z0-9_]+$')
    email: str = Field(..., max_length=254, regex=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    role: str = Field("user", regex=r'^(user|admin|moderator)$')
    
    @validator('email')
    def validate_email_domain(cls, v):
        """Additional custom validation for email domain"""
        if v.endswith('.test') or v.endswith('.invalid'):
            raise ValueError('Invalid email domain')
        return v.lower()
    
    @validator('username')
    def validate_username_reserved(cls, v):
        """Check for reserved usernames"""
        reserved = ['admin', 'root', 'system', 'null', 'undefined']
        if v.lower() in reserved:
            raise ValueError('Username is reserved')
        return v

@app.post("/secure/user")
async def create_user_secure(user_request: CreateUserRequest):
    """
    SECURE ENDPOINT - Advanced Input Validation
    
    - Comprehensive Pydantic validation
    - Custom validators for business logic
    - SQL injection prevention
    - Proper error handling
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (user_request.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Username already exists")
        
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (user_request.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Email already exists")
        
        # Insert new user
        cursor.execute(
            "INSERT INTO users (username, email, role) VALUES (?, ?, ?)",
            (user_request.username, user_request.email, user_request.role)
        )
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return {
            "message": "User created successfully",
            "user_id": user_id,
            "username": user_request.username
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# DOCUMENTATION ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
    """API documentation and vulnerability demonstration guide"""
    return {
        "message": "CWE-20 Input Validation Demonstration API",
        "vulnerable_endpoints": {
            "GET /vulnerable/user/{user_id}": "SQL Injection vulnerability",
            "GET /vulnerable/file?filename=": "Path traversal vulnerability", 
            "GET /vulnerable/search?query=&limit=": "Multiple validation issues"
        },
        "secure_endpoints": {
            "GET /secure/user/{user_id}": "Proper parameter validation",
            "GET /secure/file?filename=": "Secure file access",
            "POST /secure/search": "Validated search with Pydantic",
            "POST /secure/user": "Comprehensive user creation validation"
        },
        "test_payloads": {
            "sql_injection": "1' OR '1'='1",
            "path_traversal": "../secret.txt",
            "command_injection": "test; rm -rf /",
            "xss": "<script>alert('xss')</script>"
        },
        "security_features": [
            "Parameterized queries",
            "Path validation and sanitization", 
            "Input type and range validation",
            "Regex pattern matching",
            "Custom business logic validation",
            "Proper error handling"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, debug=True)
)
    limit: int = Field(10, ge=1, le=100, description="Number of results (1-100)")

@app.post("/secure/search")
async def search_users_secure(search_request: SearchRequest):
    """
    SECURE ENDPOINT - Comprehensive Input Validation
    
    - Uses Pydantic model for automatic validation
    - Parameterized queries prevent SQL injection
    - Proper range validation for limit
    - Regex validation for search query
    - Structured error responses
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # SECURE: Parameterized query with LIKE
        search_pattern = f"%{search_request.query}%"
        cursor.execute(
            "SELECT id, username, email, role FROM users WHERE username LIKE ? LIMIT ?",
            (search_pattern, search_request.limit)
        )
        
        results = cursor.fetchall()
        conn.close()
        
        # Format results
        users = []
        for row in results:
            users.append({
                "id": row[0],
                "username": row[1],
                "email": row[2], 
                "role": row[3]
            })
        
        return {
            "message": f"Found {len(users)} users",
            "total_results": len(users),
            "users": users
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# ADDITIONAL SECURE VALIDATION EXAMPLES
# =============================================================================

class CreateUserRequest(BaseModel):
    """Comprehensive input validation for user creation"""
    username: str = Field(..., min_length=3, max_length=50, regex=r'^[a-zA-Z0-9_]+$')
    email: str = Field(..., max_length=254, regex=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    role: str = Field("user", regex=r'^(user|admin|moderator)$')
    
    @validator('email')
    def validate_email_domain(cls, v):
        """Additional custom validation for email domain"""
        if v.endswith('.test') or v.endswith('.invalid'):
            raise ValueError('Invalid email domain')
        return v.lower()
    
    @validator('username')
    def validate_username_reserved(cls, v):
        """Check for reserved usernames"""
        reserved = ['admin', 'root', 'system', 'null', 'undefined']
        if v.lower() in reserved:
            raise ValueError('Username is reserved')
        return v

@app.post("/secure/user")
async def create_user_secure(user_request: CreateUserRequest):
    """
    SECURE ENDPOINT - Advanced Input Validation
    
    - Comprehensive Pydantic validation
    - Custom validators for business logic
    - SQL injection prevention
    - Proper error handling
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (user_request.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Username already exists")
        
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (user_request.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Email already exists")
        
        # Insert new user
        cursor.execute(
            "INSERT INTO users (username, email, role) VALUES (?, ?, ?)",
            (user_request.username, user_request.email, user_request.role)
        )
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return {
            "message": "User created successfully",
            "user_id": user_id,
            "username": user_request.username
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# DOCUMENTATION ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
    """API documentation and vulnerability demonstration guide"""
    return {
        "message": "CWE-20 Input Validation Demonstration API",
        "vulnerable_endpoints": {
            "GET /vulnerable/user/{user_id}": "SQL Injection vulnerability",
            "GET /vulnerable/file?filename=": "Path traversal vulnerability", 
            "GET /vulnerable/search?query=&limit=": "Multiple validation issues"
        },
        "secure_endpoints": {
            "GET /secure/user/{user_id}": "Proper parameter validation",
            "GET /secure/file?filename=": "Secure file access",
            "POST /secure/search": "Validated search with Pydantic",
            "POST /secure/user": "Comprehensive user creation validation"
        },
        "test_payloads": {
            "sql_injection": "1' OR '1'='1",
            "path_traversal": "../secret.txt",
            "command_injection": "test; rm -rf /",
            "xss": "<script>alert('xss')</script>"
        },
        "security_features": [
            "Parameterized queries",
            "Path validation and sanitization", 
            "Input type and range validation",
            "Regex pattern matching",
            "Custom business logic validation",
            "Proper error handling"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, debug=True)
)):
    """
    SECURE ENDPOINT - Proper Path Validation
    
    - Validates filename format with regex
    - Restricts access to safe directory only
    - Prevents path traversal attacks
    - Proper error handling
    """
    try:
        # Define safe directory
        SAFE_DIR = PathLib("safe_files").resolve()
        
        # Validate filename doesn't contain path separators
        if '/' in filename or '\\' in filename:
            raise HTTPException(status_code=400, detail="Invalid filename: path separators not allowed")
        
        # Construct and validate file path
        file_path = SAFE_DIR / filename
        resolved_path = file_path.resolve()
        
        # Ensure the resolved path is within the safe directory
        if not str(resolved_path).startswith(str(SAFE_DIR)):
            raise HTTPException(status_code=403, detail="Access denied: path outside safe directory")
        
        # Check if file exists and is actually a file
        if not resolved_path.exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        if not resolved_path.is_file():
            raise HTTPException(status_code=400, detail="Path is not a file")
        
        # Read file content
        with open(resolved_path, 'r') as f:
            content = f.read()
        
        return {
            "message": "File read successfully",
            "filename": filename,
            "content": content
        }
        
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")


class SearchRequest(BaseModel):
    """Request model with validation for search endpoint"""
    query: str = Field(..., min_length=1, max_length=100, regex=r'^[a-zA-Z0-9\s._-]+$')
    limit: int = Field(10, ge=1, le=100, description="Number of results (1-100)")

@app.post("/secure/search")
async def search_users_secure(search_request: SearchRequest):
    """
    SECURE ENDPOINT - Comprehensive Input Validation
    
    - Uses Pydantic model for automatic validation
    - Parameterized queries prevent SQL injection
    - Proper range validation for limit
    - Regex validation for search query
    - Structured error responses
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # SECURE: Parameterized query with LIKE
        search_pattern = f"%{search_request.query}%"
        cursor.execute(
            "SELECT id, username, email, role FROM users WHERE username LIKE ? LIMIT ?",
            (search_pattern, search_request.limit)
        )
        
        results = cursor.fetchall()
        conn.close()
        
        # Format results
        users = []
        for row in results:
            users.append({
                "id": row[0],
                "username": row[1],
                "email": row[2], 
                "role": row[3]
            })
        
        return {
            "message": f"Found {len(users)} users",
            "total_results": len(users),
            "users": users
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# ADDITIONAL SECURE VALIDATION EXAMPLES
# =============================================================================

class CreateUserRequest(BaseModel):
    """Comprehensive input validation for user creation"""
    username: str = Field(..., min_length=3, max_length=50, regex=r'^[a-zA-Z0-9_]+$')
    email: str = Field(..., max_length=254, regex=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    role: str = Field("user", regex=r'^(user|admin|moderator)$')
    
    @validator('email')
    def validate_email_domain(cls, v):
        """Additional custom validation for email domain"""
        if v.endswith('.test') or v.endswith('.invalid'):
            raise ValueError('Invalid email domain')
        return v.lower()
    
    @validator('username')
    def validate_username_reserved(cls, v):
        """Check for reserved usernames"""
        reserved = ['admin', 'root', 'system', 'null', 'undefined']
        if v.lower() in reserved:
            raise ValueError('Username is reserved')
        return v

@app.post("/secure/user")
async def create_user_secure(user_request: CreateUserRequest):
    """
    SECURE ENDPOINT - Advanced Input Validation
    
    - Comprehensive Pydantic validation
    - Custom validators for business logic
    - SQL injection prevention
    - Proper error handling
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (user_request.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Username already exists")
        
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (user_request.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Email already exists")
        
        # Insert new user
        cursor.execute(
            "INSERT INTO users (username, email, role) VALUES (?, ?, ?)",
            (user_request.username, user_request.email, user_request.role)
        )
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return {
            "message": "User created successfully",
            "user_id": user_id,
            "username": user_request.username
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# DOCUMENTATION ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
    """API documentation and vulnerability demonstration guide"""
    return {
        "message": "CWE-20 Input Validation Demonstration API",
        "vulnerable_endpoints": {
            "GET /vulnerable/user/{user_id}": "SQL Injection vulnerability",
            "GET /vulnerable/file?filename=": "Path traversal vulnerability", 
            "GET /vulnerable/search?query=&limit=": "Multiple validation issues"
        },
        "secure_endpoints": {
            "GET /secure/user/{user_id}": "Proper parameter validation",
            "GET /secure/file?filename=": "Secure file access",
            "POST /secure/search": "Validated search with Pydantic",
            "POST /secure/user": "Comprehensive user creation validation"
        },
        "test_payloads": {
            "sql_injection": "1' OR '1'='1",
            "path_traversal": "../secret.txt",
            "command_injection": "test; rm -rf /",
            "xss": "<script>alert('xss')</script>"
        },
        "security_features": [
            "Parameterized queries",
            "Path validation and sanitization", 
            "Input type and range validation",
            "Regex pattern matching",
            "Custom business logic validation",
            "Proper error handling"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, debug=True)
)
    email: str = Field(..., max_length=254, pattern=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
    
    @validator('email')
    def validate_email_domain(cls, v):
        """Additional custom validation for email domain"""
        if v.endswith('.test') or v.endswith('.invalid'):
            raise ValueError('Invalid email domain')
        return v.lower()
    
    @validator('username')
    def validate_username_reserved(cls, v):
        """Check for reserved usernames"""
        reserved = ['admin', 'root', 'system', 'null', 'undefined']
        if v.lower() in reserved:
            raise ValueError('Username is reserved')
        return v

@app.post("/secure/user")
async def create_user_secure(user_request: CreateUserRequest):
    """
    SECURE ENDPOINT - Advanced Input Validation
    
    - Comprehensive Pydantic validation
    - Custom validators for business logic
    - SQL injection prevention
    - Proper error handling
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (user_request.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Username already exists")
        
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (user_request.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Email already exists")
        
        # Insert new user
        cursor.execute(
            "INSERT INTO users (username, email, role) VALUES (?, ?, ?)",
            (user_request.username, user_request.email, user_request.role)
        )
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return {
            "message": "User created successfully",
            "user_id": user_id,
            "username": user_request.username
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# DOCUMENTATION ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
    """API documentation and vulnerability demonstration guide"""
    return {
        "message": "CWE-20 Input Validation Demonstration API",
        "vulnerable_endpoints": {
            "GET /vulnerable/user/{user_id}": "SQL Injection vulnerability",
            "GET /vulnerable/file?filename=": "Path traversal vulnerability", 
            "GET /vulnerable/search?query=&limit=": "Multiple validation issues"
        },
        "secure_endpoints": {
            "GET /secure/user/{user_id}": "Proper parameter validation",
            "GET /secure/file?filename=": "Secure file access",
            "POST /secure/search": "Validated search with Pydantic",
            "POST /secure/user": "Comprehensive user creation validation"
        },
        "test_payloads": {
            "sql_injection": "1' OR '1'='1",
            "path_traversal": "../secret.txt",
            "command_injection": "test; rm -rf /",
            "xss": "<script>alert('xss')</script>"
        },
        "security_features": [
            "Parameterized queries",
            "Path validation and sanitization", 
            "Input type and range validation",
            "Regex pattern matching",
            "Custom business logic validation",
            "Proper error handling"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, debug=True)
)):
    """
    SECURE ENDPOINT - Proper Path Validation
    
    - Validates filename format with regex
    - Restricts access to safe directory only
    - Prevents path traversal attacks
    - Proper error handling
    """
    try:
        # Define safe directory
        SAFE_DIR = PathLib("safe_files").resolve()
        
        # Validate filename doesn't contain path separators
        if '/' in filename or '\\' in filename:
            raise HTTPException(status_code=400, detail="Invalid filename: path separators not allowed")
        
        # Construct and validate file path
        file_path = SAFE_DIR / filename
        resolved_path = file_path.resolve()
        
        # Ensure the resolved path is within the safe directory
        if not str(resolved_path).startswith(str(SAFE_DIR)):
            raise HTTPException(status_code=403, detail="Access denied: path outside safe directory")
        
        # Check if file exists and is actually a file
        if not resolved_path.exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        if not resolved_path.is_file():
            raise HTTPException(status_code=400, detail="Path is not a file")
        
        # Read file content
        with open(resolved_path, 'r') as f:
            content = f.read()
        
        return {
            "message": "File read successfully",
            "filename": filename,
            "content": content
        }
        
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")


class SearchRequest(BaseModel):
    """Request model with validation for search endpoint"""
    query: str = Field(..., min_length=1, max_length=100, regex=r'^[a-zA-Z0-9\s._-]+$')
    limit: int = Field(10, ge=1, le=100, description="Number of results (1-100)")

@app.post("/secure/search")
async def search_users_secure(search_request: SearchRequest):
    """
    SECURE ENDPOINT - Comprehensive Input Validation
    
    - Uses Pydantic model for automatic validation
    - Parameterized queries prevent SQL injection
    - Proper range validation for limit
    - Regex validation for search query
    - Structured error responses
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # SECURE: Parameterized query with LIKE
        search_pattern = f"%{search_request.query}%"
        cursor.execute(
            "SELECT id, username, email, role FROM users WHERE username LIKE ? LIMIT ?",
            (search_pattern, search_request.limit)
        )
        
        results = cursor.fetchall()
        conn.close()
        
        # Format results
        users = []
        for row in results:
            users.append({
                "id": row[0],
                "username": row[1],
                "email": row[2], 
                "role": row[3]
            })
        
        return {
            "message": f"Found {len(users)} users",
            "total_results": len(users),
            "users": users
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# ADDITIONAL SECURE VALIDATION EXAMPLES
# =============================================================================

class CreateUserRequest(BaseModel):
    """Comprehensive input validation for user creation"""
    username: str = Field(..., min_length=3, max_length=50, regex=r'^[a-zA-Z0-9_]+$')
    email: str = Field(..., max_length=254, regex=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    role: str = Field("user", regex=r'^(user|admin|moderator)$')
    
    @validator('email')
    def validate_email_domain(cls, v):
        """Additional custom validation for email domain"""
        if v.endswith('.test') or v.endswith('.invalid'):
            raise ValueError('Invalid email domain')
        return v.lower()
    
    @validator('username')
    def validate_username_reserved(cls, v):
        """Check for reserved usernames"""
        reserved = ['admin', 'root', 'system', 'null', 'undefined']
        if v.lower() in reserved:
            raise ValueError('Username is reserved')
        return v

@app.post("/secure/user")
async def create_user_secure(user_request: CreateUserRequest):
    """
    SECURE ENDPOINT - Advanced Input Validation
    
    - Comprehensive Pydantic validation
    - Custom validators for business logic
    - SQL injection prevention
    - Proper error handling
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (user_request.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Username already exists")
        
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (user_request.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Email already exists")
        
        # Insert new user
        cursor.execute(
            "INSERT INTO users (username, email, role) VALUES (?, ?, ?)",
            (user_request.username, user_request.email, user_request.role)
        )
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return {
            "message": "User created successfully",
            "user_id": user_id,
            "username": user_request.username
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# DOCUMENTATION ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
    """API documentation and vulnerability demonstration guide"""
    return {
        "message": "CWE-20 Input Validation Demonstration API",
        "vulnerable_endpoints": {
            "GET /vulnerable/user/{user_id}": "SQL Injection vulnerability",
            "GET /vulnerable/file?filename=": "Path traversal vulnerability", 
            "GET /vulnerable/search?query=&limit=": "Multiple validation issues"
        },
        "secure_endpoints": {
            "GET /secure/user/{user_id}": "Proper parameter validation",
            "GET /secure/file?filename=": "Secure file access",
            "POST /secure/search": "Validated search with Pydantic",
            "POST /secure/user": "Comprehensive user creation validation"
        },
        "test_payloads": {
            "sql_injection": "1' OR '1'='1",
            "path_traversal": "../secret.txt",
            "command_injection": "test; rm -rf /",
            "xss": "<script>alert('xss')</script>"
        },
        "security_features": [
            "Parameterized queries",
            "Path validation and sanitization", 
            "Input type and range validation",
            "Regex pattern matching",
            "Custom business logic validation",
            "Proper error handling"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, debug=True)
)
    limit: int = Field(10, ge=1, le=100, description="Number of results (1-100)")

@app.post("/secure/search")
async def search_users_secure(search_request: SearchRequest):
    """
    SECURE ENDPOINT - Comprehensive Input Validation
    
    - Uses Pydantic model for automatic validation
    - Parameterized queries prevent SQL injection
    - Proper range validation for limit
    - Regex validation for search query
    - Structured error responses
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # SECURE: Parameterized query with LIKE
        search_pattern = f"%{search_request.query}%"
        cursor.execute(
            "SELECT id, username, email, role FROM users WHERE username LIKE ? LIMIT ?",
            (search_pattern, search_request.limit)
        )
        
        results = cursor.fetchall()
        conn.close()
        
        # Format results
        users = []
        for row in results:
            users.append({
                "id": row[0],
                "username": row[1],
                "email": row[2], 
                "role": row[3]
            })
        
        return {
            "message": f"Found {len(users)} users",
            "total_results": len(users),
            "users": users
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# ADDITIONAL SECURE VALIDATION EXAMPLES
# =============================================================================

class CreateUserRequest(BaseModel):
    """Comprehensive input validation for user creation"""
    username: str = Field(..., min_length=3, max_length=50, regex=r'^[a-zA-Z0-9_]+$')
    email: str = Field(..., max_length=254, regex=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    role: str = Field("user", regex=r'^(user|admin|moderator)$')
    
    @validator('email')
    def validate_email_domain(cls, v):
        """Additional custom validation for email domain"""
        if v.endswith('.test') or v.endswith('.invalid'):
            raise ValueError('Invalid email domain')
        return v.lower()
    
    @validator('username')
    def validate_username_reserved(cls, v):
        """Check for reserved usernames"""
        reserved = ['admin', 'root', 'system', 'null', 'undefined']
        if v.lower() in reserved:
            raise ValueError('Username is reserved')
        return v

@app.post("/secure/user")
async def create_user_secure(user_request: CreateUserRequest):
    """
    SECURE ENDPOINT - Advanced Input Validation
    
    - Comprehensive Pydantic validation
    - Custom validators for business logic
    - SQL injection prevention
    - Proper error handling
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (user_request.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Username already exists")
        
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (user_request.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Email already exists")
        
        # Insert new user
        cursor.execute(
            "INSERT INTO users (username, email, role) VALUES (?, ?, ?)",
            (user_request.username, user_request.email, user_request.role)
        )
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return {
            "message": "User created successfully",
            "user_id": user_id,
            "username": user_request.username
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# DOCUMENTATION ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
    """API documentation and vulnerability demonstration guide"""
    return {
        "message": "CWE-20 Input Validation Demonstration API",
        "vulnerable_endpoints": {
            "GET /vulnerable/user/{user_id}": "SQL Injection vulnerability",
            "GET /vulnerable/file?filename=": "Path traversal vulnerability", 
            "GET /vulnerable/search?query=&limit=": "Multiple validation issues"
        },
        "secure_endpoints": {
            "GET /secure/user/{user_id}": "Proper parameter validation",
            "GET /secure/file?filename=": "Secure file access",
            "POST /secure/search": "Validated search with Pydantic",
            "POST /secure/user": "Comprehensive user creation validation"
        },
        "test_payloads": {
            "sql_injection": "1' OR '1'='1",
            "path_traversal": "../secret.txt",
            "command_injection": "test; rm -rf /",
            "xss": "<script>alert('xss')</script>"
        },
        "security_features": [
            "Parameterized queries",
            "Path validation and sanitization", 
            "Input type and range validation",
            "Regex pattern matching",
            "Custom business logic validation",
            "Proper error handling"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, debug=True)
)):
    """
    SECURE ENDPOINT - Proper Path Validation
    
    - Validates filename format with regex
    - Restricts access to safe directory only
    - Prevents path traversal attacks
    - Proper error handling
    """
    try:
        # Define safe directory
        SAFE_DIR = PathLib("safe_files").resolve()
        
        # Validate filename doesn't contain path separators
        if '/' in filename or '\\' in filename:
            raise HTTPException(status_code=400, detail="Invalid filename: path separators not allowed")
        
        # Construct and validate file path
        file_path = SAFE_DIR / filename
        resolved_path = file_path.resolve()
        
        # Ensure the resolved path is within the safe directory
        if not str(resolved_path).startswith(str(SAFE_DIR)):
            raise HTTPException(status_code=403, detail="Access denied: path outside safe directory")
        
        # Check if file exists and is actually a file
        if not resolved_path.exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        if not resolved_path.is_file():
            raise HTTPException(status_code=400, detail="Path is not a file")
        
        # Read file content
        with open(resolved_path, 'r') as f:
            content = f.read()
        
        return {
            "message": "File read successfully",
            "filename": filename,
            "content": content
        }
        
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")


class SearchRequest(BaseModel):
    """Request model with validation for search endpoint"""
    query: str = Field(..., min_length=1, max_length=100, regex=r'^[a-zA-Z0-9\s._-]+$')
    limit: int = Field(10, ge=1, le=100, description="Number of results (1-100)")

@app.post("/secure/search")
async def search_users_secure(search_request: SearchRequest):
    """
    SECURE ENDPOINT - Comprehensive Input Validation
    
    - Uses Pydantic model for automatic validation
    - Parameterized queries prevent SQL injection
    - Proper range validation for limit
    - Regex validation for search query
    - Structured error responses
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # SECURE: Parameterized query with LIKE
        search_pattern = f"%{search_request.query}%"
        cursor.execute(
            "SELECT id, username, email, role FROM users WHERE username LIKE ? LIMIT ?",
            (search_pattern, search_request.limit)
        )
        
        results = cursor.fetchall()
        conn.close()
        
        # Format results
        users = []
        for row in results:
            users.append({
                "id": row[0],
                "username": row[1],
                "email": row[2], 
                "role": row[3]
            })
        
        return {
            "message": f"Found {len(users)} users",
            "total_results": len(users),
            "users": users
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# ADDITIONAL SECURE VALIDATION EXAMPLES
# =============================================================================

class CreateUserRequest(BaseModel):
    """Comprehensive input validation for user creation"""
    username: str = Field(..., min_length=3, max_length=50, regex=r'^[a-zA-Z0-9_]+$')
    email: str = Field(..., max_length=254, regex=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    role: str = Field("user", regex=r'^(user|admin|moderator)$')
    
    @validator('email')
    def validate_email_domain(cls, v):
        """Additional custom validation for email domain"""
        if v.endswith('.test') or v.endswith('.invalid'):
            raise ValueError('Invalid email domain')
        return v.lower()
    
    @validator('username')
    def validate_username_reserved(cls, v):
        """Check for reserved usernames"""
        reserved = ['admin', 'root', 'system', 'null', 'undefined']
        if v.lower() in reserved:
            raise ValueError('Username is reserved')
        return v

@app.post("/secure/user")
async def create_user_secure(user_request: CreateUserRequest):
    """
    SECURE ENDPOINT - Advanced Input Validation
    
    - Comprehensive Pydantic validation
    - Custom validators for business logic
    - SQL injection prevention
    - Proper error handling
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (user_request.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Username already exists")
        
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (user_request.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Email already exists")
        
        # Insert new user
        cursor.execute(
            "INSERT INTO users (username, email, role) VALUES (?, ?, ?)",
            (user_request.username, user_request.email, user_request.role)
        )
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return {
            "message": "User created successfully",
            "user_id": user_id,
            "username": user_request.username
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# DOCUMENTATION ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
    """API documentation and vulnerability demonstration guide"""
    return {
        "message": "CWE-20 Input Validation Demonstration API",
        "vulnerable_endpoints": {
            "GET /vulnerable/user/{user_id}": "SQL Injection vulnerability",
            "GET /vulnerable/file?filename=": "Path traversal vulnerability", 
            "GET /vulnerable/search?query=&limit=": "Multiple validation issues"
        },
        "secure_endpoints": {
            "GET /secure/user/{user_id}": "Proper parameter validation",
            "GET /secure/file?filename=": "Secure file access",
            "POST /secure/search": "Validated search with Pydantic",
            "POST /secure/user": "Comprehensive user creation validation"
        },
        "test_payloads": {
            "sql_injection": "1' OR '1'='1",
            "path_traversal": "../secret.txt",
            "command_injection": "test; rm -rf /",
            "xss": "<script>alert('xss')</script>"
        },
        "security_features": [
            "Parameterized queries",
            "Path validation and sanitization", 
            "Input type and range validation",
            "Regex pattern matching",
            "Custom business logic validation",
            "Proper error handling"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, debug=True)
)
    role: str = Field("user", pattern=r'^(user|admin|moderator)
    
    @validator('email')
    def validate_email_domain(cls, v):
        """Additional custom validation for email domain"""
        if v.endswith('.test') or v.endswith('.invalid'):
            raise ValueError('Invalid email domain')
        return v.lower()
    
    @validator('username')
    def validate_username_reserved(cls, v):
        """Check for reserved usernames"""
        reserved = ['admin', 'root', 'system', 'null', 'undefined']
        if v.lower() in reserved:
            raise ValueError('Username is reserved')
        return v

@app.post("/secure/user")
async def create_user_secure(user_request: CreateUserRequest):
    """
    SECURE ENDPOINT - Advanced Input Validation
    
    - Comprehensive Pydantic validation
    - Custom validators for business logic
    - SQL injection prevention
    - Proper error handling
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (user_request.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Username already exists")
        
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (user_request.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Email already exists")
        
        # Insert new user
        cursor.execute(
            "INSERT INTO users (username, email, role) VALUES (?, ?, ?)",
            (user_request.username, user_request.email, user_request.role)
        )
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return {
            "message": "User created successfully",
            "user_id": user_id,
            "username": user_request.username
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# DOCUMENTATION ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
    """API documentation and vulnerability demonstration guide"""
    return {
        "message": "CWE-20 Input Validation Demonstration API",
        "vulnerable_endpoints": {
            "GET /vulnerable/user/{user_id}": "SQL Injection vulnerability",
            "GET /vulnerable/file?filename=": "Path traversal vulnerability", 
            "GET /vulnerable/search?query=&limit=": "Multiple validation issues"
        },
        "secure_endpoints": {
            "GET /secure/user/{user_id}": "Proper parameter validation",
            "GET /secure/file?filename=": "Secure file access",
            "POST /secure/search": "Validated search with Pydantic",
            "POST /secure/user": "Comprehensive user creation validation"
        },
        "test_payloads": {
            "sql_injection": "1' OR '1'='1",
            "path_traversal": "../secret.txt",
            "command_injection": "test; rm -rf /",
            "xss": "<script>alert('xss')</script>"
        },
        "security_features": [
            "Parameterized queries",
            "Path validation and sanitization", 
            "Input type and range validation",
            "Regex pattern matching",
            "Custom business logic validation",
            "Proper error handling"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, debug=True)
)):
    """
    SECURE ENDPOINT - Proper Path Validation
    
    - Validates filename format with regex
    - Restricts access to safe directory only
    - Prevents path traversal attacks
    - Proper error handling
    """
    try:
        # Define safe directory
        SAFE_DIR = PathLib("safe_files").resolve()
        
        # Validate filename doesn't contain path separators
        if '/' in filename or '\\' in filename:
            raise HTTPException(status_code=400, detail="Invalid filename: path separators not allowed")
        
        # Construct and validate file path
        file_path = SAFE_DIR / filename
        resolved_path = file_path.resolve()
        
        # Ensure the resolved path is within the safe directory
        if not str(resolved_path).startswith(str(SAFE_DIR)):
            raise HTTPException(status_code=403, detail="Access denied: path outside safe directory")
        
        # Check if file exists and is actually a file
        if not resolved_path.exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        if not resolved_path.is_file():
            raise HTTPException(status_code=400, detail="Path is not a file")
        
        # Read file content
        with open(resolved_path, 'r') as f:
            content = f.read()
        
        return {
            "message": "File read successfully",
            "filename": filename,
            "content": content
        }
        
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")


class SearchRequest(BaseModel):
    """Request model with validation for search endpoint"""
    query: str = Field(..., min_length=1, max_length=100, regex=r'^[a-zA-Z0-9\s._-]+$')
    limit: int = Field(10, ge=1, le=100, description="Number of results (1-100)")

@app.post("/secure/search")
async def search_users_secure(search_request: SearchRequest):
    """
    SECURE ENDPOINT - Comprehensive Input Validation
    
    - Uses Pydantic model for automatic validation
    - Parameterized queries prevent SQL injection
    - Proper range validation for limit
    - Regex validation for search query
    - Structured error responses
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # SECURE: Parameterized query with LIKE
        search_pattern = f"%{search_request.query}%"
        cursor.execute(
            "SELECT id, username, email, role FROM users WHERE username LIKE ? LIMIT ?",
            (search_pattern, search_request.limit)
        )
        
        results = cursor.fetchall()
        conn.close()
        
        # Format results
        users = []
        for row in results:
            users.append({
                "id": row[0],
                "username": row[1],
                "email": row[2], 
                "role": row[3]
            })
        
        return {
            "message": f"Found {len(users)} users",
            "total_results": len(users),
            "users": users
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# ADDITIONAL SECURE VALIDATION EXAMPLES
# =============================================================================

class CreateUserRequest(BaseModel):
    """Comprehensive input validation for user creation"""
    username: str = Field(..., min_length=3, max_length=50, regex=r'^[a-zA-Z0-9_]+$')
    email: str = Field(..., max_length=254, regex=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    role: str = Field("user", regex=r'^(user|admin|moderator)$')
    
    @validator('email')
    def validate_email_domain(cls, v):
        """Additional custom validation for email domain"""
        if v.endswith('.test') or v.endswith('.invalid'):
            raise ValueError('Invalid email domain')
        return v.lower()
    
    @validator('username')
    def validate_username_reserved(cls, v):
        """Check for reserved usernames"""
        reserved = ['admin', 'root', 'system', 'null', 'undefined']
        if v.lower() in reserved:
            raise ValueError('Username is reserved')
        return v

@app.post("/secure/user")
async def create_user_secure(user_request: CreateUserRequest):
    """
    SECURE ENDPOINT - Advanced Input Validation
    
    - Comprehensive Pydantic validation
    - Custom validators for business logic
    - SQL injection prevention
    - Proper error handling
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (user_request.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Username already exists")
        
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (user_request.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Email already exists")
        
        # Insert new user
        cursor.execute(
            "INSERT INTO users (username, email, role) VALUES (?, ?, ?)",
            (user_request.username, user_request.email, user_request.role)
        )
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return {
            "message": "User created successfully",
            "user_id": user_id,
            "username": user_request.username
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# DOCUMENTATION ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
    """API documentation and vulnerability demonstration guide"""
    return {
        "message": "CWE-20 Input Validation Demonstration API",
        "vulnerable_endpoints": {
            "GET /vulnerable/user/{user_id}": "SQL Injection vulnerability",
            "GET /vulnerable/file?filename=": "Path traversal vulnerability", 
            "GET /vulnerable/search?query=&limit=": "Multiple validation issues"
        },
        "secure_endpoints": {
            "GET /secure/user/{user_id}": "Proper parameter validation",
            "GET /secure/file?filename=": "Secure file access",
            "POST /secure/search": "Validated search with Pydantic",
            "POST /secure/user": "Comprehensive user creation validation"
        },
        "test_payloads": {
            "sql_injection": "1' OR '1'='1",
            "path_traversal": "../secret.txt",
            "command_injection": "test; rm -rf /",
            "xss": "<script>alert('xss')</script>"
        },
        "security_features": [
            "Parameterized queries",
            "Path validation and sanitization", 
            "Input type and range validation",
            "Regex pattern matching",
            "Custom business logic validation",
            "Proper error handling"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, debug=True)
)
    limit: int = Field(10, ge=1, le=100, description="Number of results (1-100)")

@app.post("/secure/search")
async def search_users_secure(search_request: SearchRequest):
    """
    SECURE ENDPOINT - Comprehensive Input Validation
    
    - Uses Pydantic model for automatic validation
    - Parameterized queries prevent SQL injection
    - Proper range validation for limit
    - Regex validation for search query
    - Structured error responses
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # SECURE: Parameterized query with LIKE
        search_pattern = f"%{search_request.query}%"
        cursor.execute(
            "SELECT id, username, email, role FROM users WHERE username LIKE ? LIMIT ?",
            (search_pattern, search_request.limit)
        )
        
        results = cursor.fetchall()
        conn.close()
        
        # Format results
        users = []
        for row in results:
            users.append({
                "id": row[0],
                "username": row[1],
                "email": row[2], 
                "role": row[3]
            })
        
        return {
            "message": f"Found {len(users)} users",
            "total_results": len(users),
            "users": users
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# ADDITIONAL SECURE VALIDATION EXAMPLES
# =============================================================================

class CreateUserRequest(BaseModel):
    """Comprehensive input validation for user creation"""
    username: str = Field(..., min_length=3, max_length=50, regex=r'^[a-zA-Z0-9_]+$')
    email: str = Field(..., max_length=254, regex=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    role: str = Field("user", regex=r'^(user|admin|moderator)$')
    
    @validator('email')
    def validate_email_domain(cls, v):
        """Additional custom validation for email domain"""
        if v.endswith('.test') or v.endswith('.invalid'):
            raise ValueError('Invalid email domain')
        return v.lower()
    
    @validator('username')
    def validate_username_reserved(cls, v):
        """Check for reserved usernames"""
        reserved = ['admin', 'root', 'system', 'null', 'undefined']
        if v.lower() in reserved:
            raise ValueError('Username is reserved')
        return v

@app.post("/secure/user")
async def create_user_secure(user_request: CreateUserRequest):
    """
    SECURE ENDPOINT - Advanced Input Validation
    
    - Comprehensive Pydantic validation
    - Custom validators for business logic
    - SQL injection prevention
    - Proper error handling
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (user_request.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Username already exists")
        
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (user_request.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Email already exists")
        
        # Insert new user
        cursor.execute(
            "INSERT INTO users (username, email, role) VALUES (?, ?, ?)",
            (user_request.username, user_request.email, user_request.role)
        )
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return {
            "message": "User created successfully",
            "user_id": user_id,
            "username": user_request.username
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# DOCUMENTATION ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
    """API documentation and vulnerability demonstration guide"""
    return {
        "message": "CWE-20 Input Validation Demonstration API",
        "vulnerable_endpoints": {
            "GET /vulnerable/user/{user_id}": "SQL Injection vulnerability",
            "GET /vulnerable/file?filename=": "Path traversal vulnerability", 
            "GET /vulnerable/search?query=&limit=": "Multiple validation issues"
        },
        "secure_endpoints": {
            "GET /secure/user/{user_id}": "Proper parameter validation",
            "GET /secure/file?filename=": "Secure file access",
            "POST /secure/search": "Validated search with Pydantic",
            "POST /secure/user": "Comprehensive user creation validation"
        },
        "test_payloads": {
            "sql_injection": "1' OR '1'='1",
            "path_traversal": "../secret.txt",
            "command_injection": "test; rm -rf /",
            "xss": "<script>alert('xss')</script>"
        },
        "security_features": [
            "Parameterized queries",
            "Path validation and sanitization", 
            "Input type and range validation",
            "Regex pattern matching",
            "Custom business logic validation",
            "Proper error handling"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, debug=True)
)):
    """
    SECURE ENDPOINT - Proper Path Validation
    
    - Validates filename format with regex
    - Restricts access to safe directory only
    - Prevents path traversal attacks
    - Proper error handling
    """
    try:
        # Define safe directory
        SAFE_DIR = PathLib("safe_files").resolve()
        
        # Validate filename doesn't contain path separators
        if '/' in filename or '\\' in filename:
            raise HTTPException(status_code=400, detail="Invalid filename: path separators not allowed")
        
        # Construct and validate file path
        file_path = SAFE_DIR / filename
        resolved_path = file_path.resolve()
        
        # Ensure the resolved path is within the safe directory
        if not str(resolved_path).startswith(str(SAFE_DIR)):
            raise HTTPException(status_code=403, detail="Access denied: path outside safe directory")
        
        # Check if file exists and is actually a file
        if not resolved_path.exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        if not resolved_path.is_file():
            raise HTTPException(status_code=400, detail="Path is not a file")
        
        # Read file content
        with open(resolved_path, 'r') as f:
            content = f.read()
        
        return {
            "message": "File read successfully",
            "filename": filename,
            "content": content
        }
        
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")


class SearchRequest(BaseModel):
    """Request model with validation for search endpoint"""
    query: str = Field(..., min_length=1, max_length=100, regex=r'^[a-zA-Z0-9\s._-]+$')
    limit: int = Field(10, ge=1, le=100, description="Number of results (1-100)")

@app.post("/secure/search")
async def search_users_secure(search_request: SearchRequest):
    """
    SECURE ENDPOINT - Comprehensive Input Validation
    
    - Uses Pydantic model for automatic validation
    - Parameterized queries prevent SQL injection
    - Proper range validation for limit
    - Regex validation for search query
    - Structured error responses
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # SECURE: Parameterized query with LIKE
        search_pattern = f"%{search_request.query}%"
        cursor.execute(
            "SELECT id, username, email, role FROM users WHERE username LIKE ? LIMIT ?",
            (search_pattern, search_request.limit)
        )
        
        results = cursor.fetchall()
        conn.close()
        
        # Format results
        users = []
        for row in results:
            users.append({
                "id": row[0],
                "username": row[1],
                "email": row[2], 
                "role": row[3]
            })
        
        return {
            "message": f"Found {len(users)} users",
            "total_results": len(users),
            "users": users
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# ADDITIONAL SECURE VALIDATION EXAMPLES
# =============================================================================

class CreateUserRequest(BaseModel):
    """Comprehensive input validation for user creation"""
    username: str = Field(..., min_length=3, max_length=50, regex=r'^[a-zA-Z0-9_]+$')
    email: str = Field(..., max_length=254, regex=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    role: str = Field("user", regex=r'^(user|admin|moderator)$')
    
    @validator('email')
    def validate_email_domain(cls, v):
        """Additional custom validation for email domain"""
        if v.endswith('.test') or v.endswith('.invalid'):
            raise ValueError('Invalid email domain')
        return v.lower()
    
    @validator('username')
    def validate_username_reserved(cls, v):
        """Check for reserved usernames"""
        reserved = ['admin', 'root', 'system', 'null', 'undefined']
        if v.lower() in reserved:
            raise ValueError('Username is reserved')
        return v

@app.post("/secure/user")
async def create_user_secure(user_request: CreateUserRequest):
    """
    SECURE ENDPOINT - Advanced Input Validation
    
    - Comprehensive Pydantic validation
    - Custom validators for business logic
    - SQL injection prevention
    - Proper error handling
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (user_request.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Username already exists")
        
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (user_request.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Email already exists")
        
        # Insert new user
        cursor.execute(
            "INSERT INTO users (username, email, role) VALUES (?, ?, ?)",
            (user_request.username, user_request.email, user_request.role)
        )
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return {
            "message": "User created successfully",
            "user_id": user_id,
            "username": user_request.username
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# DOCUMENTATION ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
    """API documentation and vulnerability demonstration guide"""
    return {
        "message": "CWE-20 Input Validation Demonstration API",
        "vulnerable_endpoints": {
            "GET /vulnerable/user/{user_id}": "SQL Injection vulnerability",
            "GET /vulnerable/file?filename=": "Path traversal vulnerability", 
            "GET /vulnerable/search?query=&limit=": "Multiple validation issues"
        },
        "secure_endpoints": {
            "GET /secure/user/{user_id}": "Proper parameter validation",
            "GET /secure/file?filename=": "Secure file access",
            "POST /secure/search": "Validated search with Pydantic",
            "POST /secure/user": "Comprehensive user creation validation"
        },
        "test_payloads": {
            "sql_injection": "1' OR '1'='1",
            "path_traversal": "../secret.txt",
            "command_injection": "test; rm -rf /",
            "xss": "<script>alert('xss')</script>"
        },
        "security_features": [
            "Parameterized queries",
            "Path validation and sanitization", 
            "Input type and range validation",
            "Regex pattern matching",
            "Custom business logic validation",
            "Proper error handling"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, debug=True)
)
    
    @validator('email')
    def validate_email_domain(cls, v):
        """Additional custom validation for email domain"""
        if v.endswith('.test') or v.endswith('.invalid'):
            raise ValueError('Invalid email domain')
        return v.lower()
    
    @validator('username')
    def validate_username_reserved(cls, v):
        """Check for reserved usernames"""
        reserved = ['admin', 'root', 'system', 'null', 'undefined']
        if v.lower() in reserved:
            raise ValueError('Username is reserved')
        return v

@app.post("/secure/user")
async def create_user_secure(user_request: CreateUserRequest):
    """
    SECURE ENDPOINT - Advanced Input Validation
    
    - Comprehensive Pydantic validation
    - Custom validators for business logic
    - SQL injection prevention
    - Proper error handling
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (user_request.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Username already exists")
        
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (user_request.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Email already exists")
        
        # Insert new user
        cursor.execute(
            "INSERT INTO users (username, email, role) VALUES (?, ?, ?)",
            (user_request.username, user_request.email, user_request.role)
        )
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return {
            "message": "User created successfully",
            "user_id": user_id,
            "username": user_request.username
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# DOCUMENTATION ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
    """API documentation and vulnerability demonstration guide"""
    return {
        "message": "CWE-20 Input Validation Demonstration API",
        "vulnerable_endpoints": {
            "GET /vulnerable/user/{user_id}": "SQL Injection vulnerability",
            "GET /vulnerable/file?filename=": "Path traversal vulnerability", 
            "GET /vulnerable/search?query=&limit=": "Multiple validation issues"
        },
        "secure_endpoints": {
            "GET /secure/user/{user_id}": "Proper parameter validation",
            "GET /secure/file?filename=": "Secure file access",
            "POST /secure/search": "Validated search with Pydantic",
            "POST /secure/user": "Comprehensive user creation validation"
        },
        "test_payloads": {
            "sql_injection": "1' OR '1'='1",
            "path_traversal": "../secret.txt",
            "command_injection": "test; rm -rf /",
            "xss": "<script>alert('xss')</script>"
        },
        "security_features": [
            "Parameterized queries",
            "Path validation and sanitization", 
            "Input type and range validation",
            "Regex pattern matching",
            "Custom business logic validation",
            "Proper error handling"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, debug=True)
)):
    """
    SECURE ENDPOINT - Proper Path Validation
    
    - Validates filename format with regex
    - Restricts access to safe directory only
    - Prevents path traversal attacks
    - Proper error handling
    """
    try:
        # Define safe directory
        SAFE_DIR = PathLib("safe_files").resolve()
        
        # Validate filename doesn't contain path separators
        if '/' in filename or '\\' in filename:
            raise HTTPException(status_code=400, detail="Invalid filename: path separators not allowed")
        
        # Construct and validate file path
        file_path = SAFE_DIR / filename
        resolved_path = file_path.resolve()
        
        # Ensure the resolved path is within the safe directory
        if not str(resolved_path).startswith(str(SAFE_DIR)):
            raise HTTPException(status_code=403, detail="Access denied: path outside safe directory")
        
        # Check if file exists and is actually a file
        if not resolved_path.exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        if not resolved_path.is_file():
            raise HTTPException(status_code=400, detail="Path is not a file")
        
        # Read file content
        with open(resolved_path, 'r') as f:
            content = f.read()
        
        return {
            "message": "File read successfully",
            "filename": filename,
            "content": content
        }
        
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")


class SearchRequest(BaseModel):
    """Request model with validation for search endpoint"""
    query: str = Field(..., min_length=1, max_length=100, regex=r'^[a-zA-Z0-9\s._-]+$')
    limit: int = Field(10, ge=1, le=100, description="Number of results (1-100)")

@app.post("/secure/search")
async def search_users_secure(search_request: SearchRequest):
    """
    SECURE ENDPOINT - Comprehensive Input Validation
    
    - Uses Pydantic model for automatic validation
    - Parameterized queries prevent SQL injection
    - Proper range validation for limit
    - Regex validation for search query
    - Structured error responses
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # SECURE: Parameterized query with LIKE
        search_pattern = f"%{search_request.query}%"
        cursor.execute(
            "SELECT id, username, email, role FROM users WHERE username LIKE ? LIMIT ?",
            (search_pattern, search_request.limit)
        )
        
        results = cursor.fetchall()
        conn.close()
        
        # Format results
        users = []
        for row in results:
            users.append({
                "id": row[0],
                "username": row[1],
                "email": row[2], 
                "role": row[3]
            })
        
        return {
            "message": f"Found {len(users)} users",
            "total_results": len(users),
            "users": users
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# ADDITIONAL SECURE VALIDATION EXAMPLES
# =============================================================================

class CreateUserRequest(BaseModel):
    """Comprehensive input validation for user creation"""
    username: str = Field(..., min_length=3, max_length=50, regex=r'^[a-zA-Z0-9_]+$')
    email: str = Field(..., max_length=254, regex=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    role: str = Field("user", regex=r'^(user|admin|moderator)$')
    
    @validator('email')
    def validate_email_domain(cls, v):
        """Additional custom validation for email domain"""
        if v.endswith('.test') or v.endswith('.invalid'):
            raise ValueError('Invalid email domain')
        return v.lower()
    
    @validator('username')
    def validate_username_reserved(cls, v):
        """Check for reserved usernames"""
        reserved = ['admin', 'root', 'system', 'null', 'undefined']
        if v.lower() in reserved:
            raise ValueError('Username is reserved')
        return v

@app.post("/secure/user")
async def create_user_secure(user_request: CreateUserRequest):
    """
    SECURE ENDPOINT - Advanced Input Validation
    
    - Comprehensive Pydantic validation
    - Custom validators for business logic
    - SQL injection prevention
    - Proper error handling
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (user_request.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Username already exists")
        
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (user_request.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Email already exists")
        
        # Insert new user
        cursor.execute(
            "INSERT INTO users (username, email, role) VALUES (?, ?, ?)",
            (user_request.username, user_request.email, user_request.role)
        )
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return {
            "message": "User created successfully",
            "user_id": user_id,
            "username": user_request.username
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# DOCUMENTATION ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
    """API documentation and vulnerability demonstration guide"""
    return {
        "message": "CWE-20 Input Validation Demonstration API",
        "vulnerable_endpoints": {
            "GET /vulnerable/user/{user_id}": "SQL Injection vulnerability",
            "GET /vulnerable/file?filename=": "Path traversal vulnerability", 
            "GET /vulnerable/search?query=&limit=": "Multiple validation issues"
        },
        "secure_endpoints": {
            "GET /secure/user/{user_id}": "Proper parameter validation",
            "GET /secure/file?filename=": "Secure file access",
            "POST /secure/search": "Validated search with Pydantic",
            "POST /secure/user": "Comprehensive user creation validation"
        },
        "test_payloads": {
            "sql_injection": "1' OR '1'='1",
            "path_traversal": "../secret.txt",
            "command_injection": "test; rm -rf /",
            "xss": "<script>alert('xss')</script>"
        },
        "security_features": [
            "Parameterized queries",
            "Path validation and sanitization", 
            "Input type and range validation",
            "Regex pattern matching",
            "Custom business logic validation",
            "Proper error handling"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, debug=True)
)
    limit: int = Field(10, ge=1, le=100, description="Number of results (1-100)")

@app.post("/secure/search")
async def search_users_secure(search_request: SearchRequest):
    """
    SECURE ENDPOINT - Comprehensive Input Validation
    
    - Uses Pydantic model for automatic validation
    - Parameterized queries prevent SQL injection
    - Proper range validation for limit
    - Regex validation for search query
    - Structured error responses
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # SECURE: Parameterized query with LIKE
        search_pattern = f"%{search_request.query}%"
        cursor.execute(
            "SELECT id, username, email, role FROM users WHERE username LIKE ? LIMIT ?",
            (search_pattern, search_request.limit)
        )
        
        results = cursor.fetchall()
        conn.close()
        
        # Format results
        users = []
        for row in results:
            users.append({
                "id": row[0],
                "username": row[1],
                "email": row[2], 
                "role": row[3]
            })
        
        return {
            "message": f"Found {len(users)} users",
            "total_results": len(users),
            "users": users
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# ADDITIONAL SECURE VALIDATION EXAMPLES
# =============================================================================

class CreateUserRequest(BaseModel):
    """Comprehensive input validation for user creation"""
    username: str = Field(..., min_length=3, max_length=50, regex=r'^[a-zA-Z0-9_]+$')
    email: str = Field(..., max_length=254, regex=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    role: str = Field("user", regex=r'^(user|admin|moderator)$')
    
    @validator('email')
    def validate_email_domain(cls, v):
        """Additional custom validation for email domain"""
        if v.endswith('.test') or v.endswith('.invalid'):
            raise ValueError('Invalid email domain')
        return v.lower()
    
    @validator('username')
    def validate_username_reserved(cls, v):
        """Check for reserved usernames"""
        reserved = ['admin', 'root', 'system', 'null', 'undefined']
        if v.lower() in reserved:
            raise ValueError('Username is reserved')
        return v

@app.post("/secure/user")
async def create_user_secure(user_request: CreateUserRequest):
    """
    SECURE ENDPOINT - Advanced Input Validation
    
    - Comprehensive Pydantic validation
    - Custom validators for business logic
    - SQL injection prevention
    - Proper error handling
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (user_request.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Username already exists")
        
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (user_request.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Email already exists")
        
        # Insert new user
        cursor.execute(
            "INSERT INTO users (username, email, role) VALUES (?, ?, ?)",
            (user_request.username, user_request.email, user_request.role)
        )
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return {
            "message": "User created successfully",
            "user_id": user_id,
            "username": user_request.username
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# DOCUMENTATION ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
    """API documentation and vulnerability demonstration guide"""
    return {
        "message": "CWE-20 Input Validation Demonstration API",
        "vulnerable_endpoints": {
            "GET /vulnerable/user/{user_id}": "SQL Injection vulnerability",
            "GET /vulnerable/file?filename=": "Path traversal vulnerability", 
            "GET /vulnerable/search?query=&limit=": "Multiple validation issues"
        },
        "secure_endpoints": {
            "GET /secure/user/{user_id}": "Proper parameter validation",
            "GET /secure/file?filename=": "Secure file access",
            "POST /secure/search": "Validated search with Pydantic",
            "POST /secure/user": "Comprehensive user creation validation"
        },
        "test_payloads": {
            "sql_injection": "1' OR '1'='1",
            "path_traversal": "../secret.txt",
            "command_injection": "test; rm -rf /",
            "xss": "<script>alert('xss')</script>"
        },
        "security_features": [
            "Parameterized queries",
            "Path validation and sanitization", 
            "Input type and range validation",
            "Regex pattern matching",
            "Custom business logic validation",
            "Proper error handling"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, debug=True)
)):
    """
    SECURE ENDPOINT - Proper Path Validation
    
    - Validates filename format with regex
    - Restricts access to safe directory only
    - Prevents path traversal attacks
    - Proper error handling
    """
    try:
        # Define safe directory
        SAFE_DIR = PathLib("safe_files").resolve()
        
        # Validate filename doesn't contain path separators
        if '/' in filename or '\\' in filename:
            raise HTTPException(status_code=400, detail="Invalid filename: path separators not allowed")
        
        # Construct and validate file path
        file_path = SAFE_DIR / filename
        resolved_path = file_path.resolve()
        
        # Ensure the resolved path is within the safe directory
        if not str(resolved_path).startswith(str(SAFE_DIR)):
            raise HTTPException(status_code=403, detail="Access denied: path outside safe directory")
        
        # Check if file exists and is actually a file
        if not resolved_path.exists():
            raise HTTPException(status_code=404, detail="File not found")
        
        if not resolved_path.is_file():
            raise HTTPException(status_code=400, detail="Path is not a file")
        
        # Read file content
        with open(resolved_path, 'r') as f:
            content = f.read()
        
        return {
            "message": "File read successfully",
            "filename": filename,
            "content": content
        }
        
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")


class SearchRequest(BaseModel):
    """Request model with validation for search endpoint"""
    query: str = Field(..., min_length=1, max_length=100, regex=r'^[a-zA-Z0-9\s._-]+$')
    limit: int = Field(10, ge=1, le=100, description="Number of results (1-100)")

@app.post("/secure/search")
async def search_users_secure(search_request: SearchRequest):
    """
    SECURE ENDPOINT - Comprehensive Input Validation
    
    - Uses Pydantic model for automatic validation
    - Parameterized queries prevent SQL injection
    - Proper range validation for limit
    - Regex validation for search query
    - Structured error responses
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # SECURE: Parameterized query with LIKE
        search_pattern = f"%{search_request.query}%"
        cursor.execute(
            "SELECT id, username, email, role FROM users WHERE username LIKE ? LIMIT ?",
            (search_pattern, search_request.limit)
        )
        
        results = cursor.fetchall()
        conn.close()
        
        # Format results
        users = []
        for row in results:
            users.append({
                "id": row[0],
                "username": row[1],
                "email": row[2], 
                "role": row[3]
            })
        
        return {
            "message": f"Found {len(users)} users",
            "total_results": len(users),
            "users": users
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# ADDITIONAL SECURE VALIDATION EXAMPLES
# =============================================================================

class CreateUserRequest(BaseModel):
    """Comprehensive input validation for user creation"""
    username: str = Field(..., min_length=3, max_length=50, regex=r'^[a-zA-Z0-9_]+$')
    email: str = Field(..., max_length=254, regex=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    role: str = Field("user", regex=r'^(user|admin|moderator)$')
    
    @validator('email')
    def validate_email_domain(cls, v):
        """Additional custom validation for email domain"""
        if v.endswith('.test') or v.endswith('.invalid'):
            raise ValueError('Invalid email domain')
        return v.lower()
    
    @validator('username')
    def validate_username_reserved(cls, v):
        """Check for reserved usernames"""
        reserved = ['admin', 'root', 'system', 'null', 'undefined']
        if v.lower() in reserved:
            raise ValueError('Username is reserved')
        return v

@app.post("/secure/user")
async def create_user_secure(user_request: CreateUserRequest):
    """
    SECURE ENDPOINT - Advanced Input Validation
    
    - Comprehensive Pydantic validation
    - Custom validators for business logic
    - SQL injection prevention
    - Proper error handling
    """
    try:
        conn = sqlite3.connect('demo.db')
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (user_request.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Username already exists")
        
        # Check if email already exists
        cursor.execute("SELECT id FROM users WHERE email = ?", (user_request.email,))
        if cursor.fetchone():
            raise HTTPException(status_code=409, detail="Email already exists")
        
        # Insert new user
        cursor.execute(
            "INSERT INTO users (username, email, role) VALUES (?, ?, ?)",
            (user_request.username, user_request.email, user_request.role)
        )
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return {
            "message": "User created successfully",
            "user_id": user_id,
            "username": user_request.username
        }
        
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Database error")


# =============================================================================
# DOCUMENTATION ENDPOINTS
# =============================================================================

@app.get("/")
async def root():
    """API documentation and vulnerability demonstration guide"""
    return {
        "message": "CWE-20 Input Validation Demonstration API",
        "vulnerable_endpoints": {
            "GET /vulnerable/user/{user_id}": "SQL Injection vulnerability",
            "GET /vulnerable/file?filename=": "Path traversal vulnerability", 
            "GET /vulnerable/search?query=&limit=": "Multiple validation issues"
        },
        "secure_endpoints": {
            "GET /secure/user/{user_id}": "Proper parameter validation",
            "GET /secure/file?filename=": "Secure file access",
            "POST /secure/search": "Validated search with Pydantic",
            "POST /secure/user": "Comprehensive user creation validation"
        },
        "test_payloads": {
            "sql_injection": "1' OR '1'='1",
            "path_traversal": "../secret.txt",
            "command_injection": "test; rm -rf /",
            "xss": "<script>alert('xss')</script>"
        },
        "security_features": [
            "Parameterized queries",
            "Path validation and sanitization", 
            "Input type and range validation",
            "Regex pattern matching",
            "Custom business logic validation",
            "Proper error handling"
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, debug=True)