import sys
sys.path.append("..")

from starlette.responses import RedirectResponse

from fastapi import Depends, HTTPException, status, APIRouter, Request, Response, Form
from pydantic import BaseModel
from typing import Optional
import models
from models import UserType
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from database import SessionLocal, engine
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from datetime import datetime, timedelta
from jose import jwt, JWTError

from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import re
from sqlalchemy.orm import Session
from fastapi import Request











SECRET_KEY = "KlgH6AzYDeZeGwD288to79I3vTHT8wp7"
ALGORITHM = "HS256"

templates = Jinja2Templates(directory="templates")

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

models.Base.metadata.create_all(bind=engine)

oauth2_bearer = OAuth2PasswordBearer(tokenUrl="token")


router = APIRouter(
    prefix="/auth",
    tags=["auth"],
    responses={401: {"user": "Not authorized"}}
)


class LoginForm:
    def __init__(self, request: Request):
        self.request: Request = request
        self.username: Optional[str] = None
        self.password: Optional[str] = None

    async def create_oauth_form(self):
        form = await self.request.form()
        self.username = form.get("email")
        self.password = form.get("password")


def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()


def get_password_hash(password):
    return bcrypt_context.hash(password)


def verify_password(plain_password, hashed_password):
    return bcrypt_context.verify(plain_password, hashed_password)


def authenticate_user(username: str, password: str, db):
    user = db.query(models.Users)\
        .filter(models.Users.username == username)\
        .first()

    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(username: str, user_id: int,email: str, first_name: str,last_name: str,user_type: UserType, expires_delta: Optional[timedelta] = None):
    encode = {"sub": username, "id": user_id,"email": email, "first_name": first_name,"last_name":last_name,"user_type": user_type.value }
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    encode.update({"exp": expire})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)





async def get_current_user(request: Request):
    try:
        token = request.cookies.get("access_token")
        if token is None:
            return None
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("id")
        email: str = payload.get("email")
        first_name: str = payload.get("first_name")
        last_name: str = payload.get("last_name")
        user_type: str = payload.get("user_type")
        if username is None or user_id is None:
            logout(request)
        return {"username": username, "id": user_id,"email": email,"first_name": first_name, "last_name": last_name, "user_type": user_type}
    except JWTError:
        raise HTTPException(status_code=404, detail="Not found")
    

@router.post("/token")
async def login_for_access_token(response: Response, form_data: OAuth2PasswordRequestForm = Depends(),
                                 db: Session = Depends(get_db)):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        return False
    token_expires = timedelta(minutes=60)
    token = create_access_token(user.username, user.id,user.email, user.first_name, user.last_name,user.user_type,expires_delta=token_expires)

    response.set_cookie(key="access_token", value=token, httponly=True)

    return True



def generate_suggested_usernames(firstname: str, lastname: str, db: Session, count: int = 3):
    suggestions = []

    #  suggestion based on the first and last names
    base_suggestion = f"{firstname.lower()}.{lastname.lower()}"
    base_suggestion = re.sub(r'[^a-zA-Z0-9]', '', base_suggestion)[:20]

    for i in range(count):
        suggestion = base_suggestion + str(i + 1)
        while db.query(models.Users).filter(models.Users.username == suggestion).first():
            i += 1
            suggestion = base_suggestion + str(i + 1)
        suggestions.append(suggestion)

    return suggestions

def get_base_url_login(request: Request):
    return request.url_for("authentication_login_page")


#register


@router.get("/register", response_class=HTMLResponse)
async def register(request: Request, get_current_user: dict = Depends(get_current_user)):
    if get_current_user:
        user_type = get_current_user.get("user_type")

        if user_type == "super_admin":
            return RedirectResponse(url=request.url_for("super_admin_todo_dashboard"))
           
        elif user_type == "user":
           return RedirectResponse(url=request.url_for("user_todo_dashboard"))
    
    return templates.TemplateResponse("auth/admin/register.html", {"request": request})





@router.post("/register", response_class=HTMLResponse)
async def register_user(request: Request, email: str = Form(...), username: str = Form(...),
                        firstname: str = Form(...), lastname: str = Form(...),
                        password: str = Form(...), password2: str = Form(...),
                        db: Session = Depends(get_db)):

    existing_username = db.query(models.Users).filter(models.Users.username == username).first()

    if existing_username:
        suggested_usernames = generate_suggested_usernames(firstname, lastname, db, count=3)
        msg = f"Username already exists. Please choose a different one. Suggested usernames: {', '.join(suggested_usernames)}"
        return templates.TemplateResponse("auth/admin/register.html", {"request": request, "msg": msg})

    existing_email = db.query(models.Users).filter(models.Users.email == email).first()

    if existing_email:
        msg = "Email address already in use. Please use a different one."
        return templates.TemplateResponse("auth/admin/register.html", {"request": request, "msg": msg})

    if password != password2:
        msg = "Passwords do not match. Please try again."
        return templates.TemplateResponse("auth/admin/register.html", {"request": request, "msg": msg})

    user_model = models.Users()
    user_model.username = username
    user_model.email = email
    user_model.first_name = firstname
    user_model.last_name = lastname

    hash_password = get_password_hash(password)
    user_model.hashed_password = hash_password
    user_model.is_active = True

    db.add(user_model)
    db.commit()

    msg = "User successfully created"
    return templates.TemplateResponse("auth/admin/login.html", {"request": request, "msg": msg})




#login

    
@router.get("/", response_class=HTMLResponse, name="authentication_login_page")
async def authentication_page(request: Request, get_current_user: dict = Depends(get_current_user)):
    if get_current_user:
        user_type = get_current_user.get("user_type")

        if user_type == "super_admin":
            return RedirectResponse(url=request.url_for("super_admin_todo_dashboard"))
           
        elif user_type == "user":
           return RedirectResponse(url=request.url_for("user_todo_dashboard"))
            

    return templates.TemplateResponse("auth/admin/login.html", {"request": request})




# @router.post("/", response_class=HTMLResponse)
# async def login(request: Request, db: Session = Depends(get_db)):
#     try:
#         form = LoginForm(request)
#         await form.create_oauth_form()
#         response = RedirectResponse(url="/todos/my-todo-app", status_code=status.HTTP_302_FOUND)

#         validate_user_cookie = await login_for_access_token(response=response, form_data=form, db=db)

#         if not validate_user_cookie:
#             msg = "Incorrect Username or Password"
#             return templates.TemplateResponse("auth/admin/login.html", {"request": request, "msg": msg})
#         return response
#     except HTTPException:
#         msg = "Unknown Error"
#         return templates.TemplateResponse("auth/admin/login.html", {"request": request, "msg": msg})

@router.post("/", response_class=HTMLResponse)
async def login(request: Request, db: Session = Depends(get_db)):
    try:
        form = LoginForm(request)
        await form.create_oauth_form()

        # Assuming your User model has a user_type field
        user = authenticate_user(form.username, form.password, db)
        if not user:
            raise HTTPException(status_code=401, detail="Incorrect Username or Password")

        token_expires = timedelta(minutes=60)
        token = create_access_token(
            user.username, user.id, user.email, user.first_name, user.last_name, user.user_type, expires_delta=token_expires
        )

        # Check the user type 
        if user.user_type == UserType.super_admin.value:
            response = RedirectResponse(url=request.url_for("super_admin_todo_dashboard"), status_code=status.HTTP_302_FOUND)
        elif user.user_type == UserType.user.value:
            response = RedirectResponse(url=request.url_for("user_todo_dashboard"), status_code=status.HTTP_302_FOUND)
        else:
            raise HTTPException(status_code=401, detail="Unknown user type")

        response.set_cookie(key="access_token", value=token, httponly=True)
        return response

    except HTTPException as e:
        msg = "Unknown Error"
        return templates.TemplateResponse("auth/admin/login.html", {"request": request, "msg": msg})

#logout

@router.get("/logout", name="authentication_logout", response_class=RedirectResponse)
async def logout(request: Request, url: str = Depends(get_base_url_login)):
    msg = "Logout Successful"
    response = RedirectResponse(url=url, status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(key="access_token")
    return response




















