from typing import Annotated
from fastapi import Depends, HTTPException, Path, APIRouter
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from starlette import status
from models import Todos, Users
from database import SessionLocal
from .auth import get_current_user

router = APIRouter(
    prefix='/users',
    tags=['users'],
)

def get_db():
  db = SessionLocal()
  try:
    yield db
  finally:
    db.close()

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]

class UserVerification(BaseModel):
  password: str
  new_password: str = Field(min_length=6)

@router.get("/myTodo", status_code=status.HTTP_200_OK)
async def read_todo(user: user_dependency,
                    db: db_dependency):
  if user is None:
    raise HTTPException(status_code=401, detail='Authentication Failed')
  todo_model = db.query(Todos).filter(Todos.owner_id == user.get('id')).all()
  if todo_model is not None:
    return todo_model

@router.patch('/change-password', status_code=status.HTTP_204_NO_CONTENT)
async def change_password(user: user_dependency, db: db_dependency,
                          user_verification: UserVerification):
  if user is None:
    raise HTTPException(status_code=401, detail='Authentication Failed')
  user_model = db.query(Users).filter(Users.id == user.get('id')).first()
  if user_model is None:
    raise HTTPException(status_code=401, detail='User not found')
  if not  bcrypt_context.verify(user_verification.password, user_model.hashed_password):
    raise HTTPException(status_code=401, detail='Incorrect password')

  user_model.hashed_password = bcrypt_context.hash(user_verification.new_password)
  db.add(user_model)
  db.commit()
