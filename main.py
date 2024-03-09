

from fastapi import FastAPI, Depends, HTTPException, Form, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import sqlite3
import bcrypt
import os
from sqlite3 import Error
from passlib.context import CryptContext

app = FastAPI()

#DB creation
#------------------------------------------------------------------

def initialize_db():
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    # Create table with id, username, and hashed_password
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

@app.on_event("startup")
async def startup_event():
    if not os.path.exists("test.db"):
        initialize_db()
        print("Database and users table created.")
    else:
        print("Database already exists.")


# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_db_connection():
    conn = sqlite3.connect('test.db')
    conn.row_factory = sqlite3.Row
    return conn

def get_user_by_username(conn, username: str):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchone()

def create_user(conn, username: str, hashed_password: str):
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()

# Login
@app.post("/login/")
async def login(username: str = Form(...), password: str = Form(...)):
    conn = get_db_connection()
    user = get_user_by_username(conn, username)
    if not user or not pwd_context.verify(password, user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    return {"message": f"Login successful for user: {username}"}

@app.get("/", response_class=HTMLResponse)
async def read_root():
    with open('login.html', 'r') as f:
        html_content = f.read()
    return HTMLResponse(content=html_content, status_code=200)


# Registration
@app.post("/register/")
async def signup(username: str = Form(...), password: str = Form(...)):
    conn = get_db_connection()
    # Check if user already exists
    if get_user_by_username(conn, username):
        raise HTTPException(status_code=400, detail="Username already registered")
    # Hash password and create user
    hashed_password = pwd_context.hash(password)
    create_user(conn, username, hashed_password)
    return {"message": "User successfully registered"}

@app.get("/register/", response_class=HTMLResponse)
async def read_signup():
    with open('Register.html', 'r') as f:
        html_content = f.read()
    return HTMLResponse(content=html_content, status_code=200)


#Change Password
@app.post("/update/")
async def signup(username: str = Form(...), password: str = Form(...)):
    conn = get_db_connection()
    try:
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already taken")
    finally:
        conn.close()
    return {"message": "User registered successfully"}

@app.get("/update/", response_class=HTMLResponse)
async def read_signup():
    with open('changepw.html', 'r') as f:
        html_content = f.read()
    return HTMLResponse(content=html_content, status_code=200)

app.mount("/static", StaticFiles(directory="static"), name="static")

