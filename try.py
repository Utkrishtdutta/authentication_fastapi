from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from pymongo import MongoClient
from bson.objectid import ObjectId
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta
from typing import Optional

app = FastAPI()

MONGO_URI = "mongodb://localhost:27017/"
DATABASE_NAME = "user_login"
USERS_COLLECTION = "user_data"

client = MongoClient(MONGO_URI)
db = client[DATABASE_NAME]
collection = db[USERS_COLLECTION]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = "user_login"  
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  

class User(BaseModel):
    username: str
    password: str


class UserInDB(User):
    _id: ObjectId


class UserCreate(User):
    password: str


class UserInResponse(User):
    id: str
    username: str


class UpdatePassword(BaseModel):
   username : str
   current_password : str
   new_password : str

class Token(BaseModel):
    access_token: str
    token_type: str


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(create_access_token)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = collection.find_one({"username": username})
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user



@app.post("/register")#, response_model=UserInResponse)
async def register(user: UserCreate):
    existing_user = collection.find_one({"username": user.username})
    if existing_user:
        raise HTTPException(status_code=status.HTTP_208_ALREADY_REPORTED, detail="Username already registered")

    hashed_password = pwd_context.hash(user.password)
    print("exis",existing_user)

    user_dict = {"username": user.username, "password": hashed_password, 'status': 'active'}
    result = collection.insert_one(user_dict)
    user_id = str(result.inserted_id)

    return {"id": user_id, "username": user.username}


@app.post("/login")#, response_model=Token)
async def login(user: User):
    db_user = collection.find_one({"username": user.username})

    if not db_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Username not found")

    if not pwd_context.verify(user.password, db_user["password"]) and db_user['status'] == 'active':
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect password")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # access_token = create_access_token(data={"sub": db_user["username"]}, expires_delta=access_token_expires)
    
    return {"response" : "Successful login"}

@app.put("/update_password")
async def update_password(user_data: dict):

    db_user = collection.find_one({"username": user_data['username']})
    if not db_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Username not found")

    if not pwd_context.verify(user_data['current_password'], db_user["password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current password is incorrect")

    hashed_password = pwd_context.hash(user_data['new_password'])
    
    update_result = collection.update_one(
        {"username": user_data['username']},
        {"$set": {"password": hashed_password}}
    )

    if update_result.modified_count == 1:
        return {"message": "Password updated successfully"}
    else:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to update password")



@app.delete("/delete_password")
async def delete_password(user_data: dict):
    print(user_data)

    db_user = collection.find_one({"username": user_data['username']})
    if not db_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Username not found")

    if not pwd_context.verify(user_data['password'], db_user["password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current password is incorrect")
    
    update_result = collection.update_one(
        {"username": user_data['username']},
        {"$set": {"status": 'inactive'}}
    )

    if update_result.modified_count == 1:
        return {"message": "User deleted successfully"}
    else:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="User not deleted successfully")


@app.get("/users/me", response_model=UserInResponse)
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return {"id": str(current_user["_id"]), "username": current_user["username"]}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8080)
