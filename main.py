from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm 
from pydantic import BaseModel
from typing import Union
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import  jwt, JWTError


SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


users_db={
    "robert":{
    "username":"robert",
    "full_name":"Restrepo",
    "email":"rr@gmail.com",
    "hashed_password":"$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
    "disabled":"False",   
    }
    
}


app=FastAPI()

oauth2 = OAuth2PasswordBearer("/token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(BaseModel):
    username:str
    full_name: Union[str, None]=None
    email:Union[str,None]=None
    disabled:Union[bool, None]=None


class UserInDb(User):
    hashed_password:str


def get_user(db, username):
    if username in db:
        user_data = db[username]
        return UserInDb(**user_data)
    return []
    
def verify_password(plane_password, hashed_password):
    return pwd_context.verify(plane_password, hashed_password)


def authenticate_user(db, username, password):
    user = get_user(db, username)
    if not user:
        raise HTTPException(status_code=401, 
                            detail="could not validate credentials",
                            headers={"WWW-Autenticate":"Bearer"})
    if not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, 
                            detail="could not validate credentials",
                            headers={"WWW-Autenticate":"Bearer"})
    return user

def create__token(data: dict, time_expire:Union[datetime, None] = None):
    data_copy = data.copy()
    if time_expire is None:
        expire = datetime.utcnow() + timedelta(minutes=15)
    else:
        expire = datetime.utcnow() + time_expire
    data_copy.update({"exp": expire})
    token_jwt = jwt.encode(data_copy, key=SECRET_KEY, algorithm=ALGORITHM)
    print(token_jwt)
    return token_jwt

def get_user_current(token: str = Depends(oauth2)):
    try:
        token_decode = jwt.decode(token, key=SECRET_KEY, algorithm=[ALGORITHM])
        username = token_decode.get("sub")
        if username == None:
            raise HTTPException(status_code=401, 
                detail="could not validate credentials",
                headers={"WWW-Autenticate":"Bearer"})
    except JWTError:
        raise HTTPException(status_code=401, detail="could not validate credentials",headers={"WWW-Autenticate":"Bearer"})
       
    user = get_user(users_db, username)
    if not user:
        raise HTTPException(status_code=401, 
                            detail="could not validate credentials",
                            headers={"WWW-Autenticate":"Bearer"})    
    return User   


def get_user_disabled_current(user = Depends(get_user_current)):
    if user.disabled:
        raise HTTPException(status_code=400, detail="inactive user")
    return user



@app.get("/")
def root():
    return "Hola Fast Api"

@app.get("/users/me")
def user(user:User = Depends(get_user_disabled_current)):
    print(user)
    return user


@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(users_db, form_data.username, form_data.password)
    print(user)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token_jwt = create__token({"sub": user.username}, access_token_expires)
    print(access_token_expires)
    #print (form_data.username, form_data.password)
    return {"acces_token":access_token_jwt,
            "token_type":"bearer"
            }


