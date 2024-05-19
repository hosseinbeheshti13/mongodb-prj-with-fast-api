from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pymongo import MongoClient
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
from typing import List
from bson import ObjectId
from jose import JWTError, jwt
from passlib.context import CryptContext
import urllib.parse


# Initialize FastAPI app
app = FastAPI()

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# MongoDB connection details
username = "dbadmin"
password = "dbImp!14@2"
encoded_username = urllib.parse.quote_plus(username)
encoded_password = urllib.parse.quote_plus(password)
MONGODB_CONNECTION_STRING = f"mongodb://{encoded_username}:{encoded_password}@78.38.35.219:27017/"
DATABASE_NAME = "99463119"

# Connect to MongoDB
client = MongoClient(MONGODB_CONNECTION_STRING)
db = client[DATABASE_NAME]

# Token settings
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# passlib context for password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 password bearer for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

# Pydantic models
class User(BaseModel):
    id: str
    username: str
    password: str
    first_name: str
    last_name: str
    image: str

class Email(BaseModel):
    sender: str
    receivers: List[str]
    subject: str
    body: str
    date: datetime = Field(default_factory=datetime.now)
    seen: bool = False

# MongoDB collections
users_collection = db["users"]
emails_collection = db["emails"]

# Token functions
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return username

# Password hashing and verification functions
def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# User authentication
def authenticate_user(username: str, password: str):
    user = users_collection.find_one({"username": username})
    if not user:
        return False
    if not verify_password(password, user["password"]):
        return False
    return user

# User endpoints
@app.post("/users/")
def create_user(user: User):
    user_data = user.dict()
    user_data["password"] = get_password_hash(user_data["password"])
    result = users_collection.insert_one(user_data)
    return {"message": "User created successfully", "user_id": str(result.inserted_id)}

# Login endpoint
@app.post("/login")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Email endpoints
@app.post("/emails/")
def send_email(email: Email, current_user: str = Depends(verify_token)):
    sender_id = current_user
    email.sender = sender_id
    email.date = datetime.now()
    if not users_collection.find_one({"_id": ObjectId(sender_id)}):
        raise HTTPException(status_code=404, detail="Sender not found")
    email_data = email.dict()
    result = emails_collection.insert_one(email_data)
    return {"message": "Email sent successfully", "email_id": str(result.inserted_id)}

@app.get("/emails/", response_model=List[dict])
def get_emails(
    receiver: str = None,
    subject: str = None,
    seen: bool = None,
    skip: int = 0,
    limit: int = 10,
    order_by_date: str = "-date"
):
    pipeline = []
    match_stage = {}
    if receiver:
        match_stage["receivers"] = receiver
    if subject:
        match_stage["subject"] = subject
    if seen is not None:
        match_stage["seen"] = seen
    if match_stage:
        pipeline.append({"$match": match_stage})
    sort_order = -1 if order_by_date.startswith("-") else 1
    sort_key = order_by_date.lstrip("-")
    pipeline.append({"$sort": {sort_key: sort_order}})
    pipeline.append({"$skip": skip})
    pipeline.append({"$limit": limit})
    emails = list(emails_collection.aggregate(pipeline))
    for email in emails:
        email["_id"] = str(email["_id"])
        del email["body"]
    return emails

@app.get("/emails/{email_id}", response_model=Email)
def get_email_by_id(email_id: str):
    email = emails_collection.find_one({"_id": ObjectId(email_id)})
    if email:
        email["_id"] = str(email["_id"])
        return email
    raise HTTPException(status_code=404, detail="Email not found")

@app.put("/emails/{email_id}")
def mark_email_as_seen(email_id: str):
    result = emails_collection.update_one({"_id": ObjectId(email_id)}, {"$set": {"seen": True}})
    if result.modified_count == 1:
        return {"message": "Email marked as seen successfully"}
    raise HTTPException(status_code=404, detail="Email not found")

@app.get("/protected_resource")
def protected_resource(current_user: str = Depends(verify_token)):
    return {"message": "This is a protected resource accessible only to authenticated users."}
