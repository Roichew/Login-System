

from fastapi import FastAPI, Depends, HTTPException, Form, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from fastapi.responses import JSONResponse
from datetime import datetime, timedelta
from pydantic import BaseModel
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
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if user and pwd_context.verify(password, user["hashed_password"]):
        # Generate a token or session (implementation depends on your application)
        return {"message": "Login successful"}
    else:
        raise HTTPException(status_code=401, detail="Incorrect username or password")


@app.get("/", response_class=HTMLResponse)
async def read_root():
    with open('login.html', 'r') as f:
        html_content = f.read()
    return HTMLResponse(content=html_content, status_code=200)


# Registration
@app.post("/register/")
async def signup(username: str = Form(...), password: str = Form(...)):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if user already exists
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Hash password and create user
    hashed_password = pwd_context.hash(password)
    cursor.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    conn.close()
    return {"message": "User successfully registered"}


@app.get("/register-page/", response_class=HTMLResponse)
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

@app.get("/update-page/", response_class=HTMLResponse)
async def read_signup():
    with open('changepw.html', 'r') as f:
        html_content = f.read()
    return HTMLResponse(content=html_content, status_code=200)

app.mount("/static", StaticFiles(directory="static"), name="static")

SECRET_KEY = "a_very_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Dummy function to get a fake user
def fake_hash_password(password: str):
    return "fakehashed" + password

# User model for demonstration purposes
class User(BaseModel):
    username: str

# Modify or replace with your actual database model
class UserInDB(User):
    hashed_password: str

# Function to authenticate user and return user if successful
def authenticate_user(fake_db, username: str, password: str):
    user = fake_db.get(username, None)
    if not user or not fake_hash_password(password) == user.hashed_password:
        return False
    return user

# Function to create access token
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(get_db_connection(), form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me")
async def read_users_me(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"},)
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = payload
    except JWTError:
        raise credentials_exception
    user = get_db_connection().get(username, None)
    if user is None:
        raise credentials_exception
    return user
