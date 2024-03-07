

from fastapi import FastAPI, Depends, HTTPException, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
import sqlite3
import bcrypt
from sqlite3 import Error

app = FastAPI()

def pw_encrypt(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password,salt)


# Database connection
def get_db_connection():
    conn = None
    try:
        conn = sqlite3.connect('test.db')
        conn.row_factory = sqlite3.Row
    except Error as e:
        print(e)
    return conn

# Initialize database (run this once)
@app.on_event("startup")
def startup():
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.close()

# Login
@app.post("/login/")
async def login(username: str = Form(...), password: str = Form(...)):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
    conn.close()
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return {"message": "Login successful"}
    else:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

@app.get("/", response_class=HTMLResponse)
async def read_root():
    with open('login.html', 'r') as f:
        html_content = f.read()
    return HTMLResponse(content=html_content, status_code=200)


# Registration
@app.post("/register/")
async def signup(username: str = Form(...), password: str = Form(...)):
    conn = get_db_connection()
    try:
        conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already taken")
    finally:
        conn.close()
    return {"message": "User registered successfully"}

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

@app.get("/uodate/", response_class=HTMLResponse)
async def read_signup():
    with open('Register.html', 'r') as f:
        html_content = f.read()
    return HTMLResponse(content=html_content, status_code=200)

app.mount("/static", StaticFiles(directory="static"), name="static")

