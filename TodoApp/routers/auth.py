from typing import Annotated
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status

from database import SessionLocal
from models import Users
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError, ExpiredSignatureError

router = APIRouter(
    prefix='/auth',
    tags=['auth'],
)

SECRET_KEY = 'f8c802d3312647686c20ecd709cd0a692f780d2976bf1ac8a5d70c03c3ff1852'
ALGORITHMS = 'HS256'

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='/auth/token')

def get_db():
  db = SessionLocal()
  try:
    yield db
  finally:
    db.close()

db_dependency = Annotated[Session, Depends(get_db)]

def authenticate_user(username: str, password: str, db):
  user = db.query(Users).filter(Users.username == username).first()
  if not user:
    return False
  if not bcrypt_context.verify(password, user.hashed_password):
    return False
  return user

class CreateUserRequest(BaseModel):
  username: str
  email: str
  first_name: str
  last_name: str
  password: str
  role: str

def create_access_token(username: str, user_id: int, role: str, expires_delta: timedelta):
  encode = {'sub': username, 'id': user_id, 'role': role}
  expires = datetime.utcnow() + expires_delta
  encode.update({'exp': expires})
  return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHMS)


async def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
  try:
    payload = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHMS)
    username: str = payload.get('sub')
    user_id: int = payload.get('id')
    user_role: str = payload.get('role')
    if username is None or user_id is None:
      raise HTTPException(
          status_code=status.HTTP_401_UNAUTHORIZED,
          detail='Could not validate credentials (missing fields)'
      )
    return {'username': username, 'id': user_id, 'user_role': user_role}
  except ExpiredSignatureError:
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Token has expired'
    )
  except JWTError as e:
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=f'Could not validate credentials ({str(e)})'
    )


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependency,
                      create_user_request: CreateUserRequest):
  create_user_model = Users(
      email=create_user_request.email,
      username=create_user_request.username,
      first_name=create_user_request.first_name,
      last_name=create_user_request.last_name,
      hashed_password=bcrypt_context.hash(create_user_request.password),
      is_active=True,
      role=create_user_request.role
  )

  db.add(create_user_model)
  db.commit()

@router.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: db_dependency):

  user = authenticate_user(form_data.username, form_data.password, db)
  if not user:
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                        detail='Could not validate credentials')

  token = create_access_token(user.username, user.id, user.role, timedelta(minutes=20))
  return {"access_token": token, "token_type": "bearer"}