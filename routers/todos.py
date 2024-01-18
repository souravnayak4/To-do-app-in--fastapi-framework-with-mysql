import sys
sys.path.append("..")

from starlette import status
from starlette.responses import RedirectResponse

from fastapi import Depends,HTTPException, APIRouter, Request, Form
import models
from database import engine, SessionLocal
from sqlalchemy.orm import Session
from .auth import get_current_user
from models import UserType
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates


router = APIRouter(
    prefix="/todos",
    tags=["todos"],
    responses={404: {"description": "Not found"}}
)

models.Base.metadata.create_all(bind=engine)

templates = Jinja2Templates(directory="templates")


def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()


def check_user_type(user: dict = Depends(get_current_user), required_type: UserType = UserType.user):
    if user is None or user.get("user_type") != required_type.value:
        raise HTTPException(
            status_code=status.HTTP_302_FOUND,
            detail="Access Denied",
            headers={"Location": "/access_denied"},
        )
    return user


def check_super_admin_access(user: dict = Depends(get_current_user)):
    return check_user_type(user, required_type=UserType.super_admin)



        


@router.get("/my-todo-app", response_class=HTMLResponse, name="super_admin_todo_dashboard")
async def read_all_super_admin(request: Request,db: Session = Depends(get_db),user: dict = Depends(check_super_admin_access)):
    todos = db.query(models.Todos).filter(models.Todos.owner_id == user.get("id")).all()
    return templates.TemplateResponse("pages/admin/todo.html", {"request": request, "todos": todos, "user": user})




@router.get("/", response_class=HTMLResponse, name="user_todo_dashboard", dependencies=[Depends(check_user_type)])
async def read_all_by_user(request: Request, db: Session = Depends(get_db), user: dict = Depends(get_current_user)):
    todos = db.query(models.Todos).filter(models.Todos.owner_id == user.get("id")).all()
    return templates.TemplateResponse("pages/user/home.html", {"request": request, "todos": todos, "user": user})




@router.get("/add-todo", response_class=HTMLResponse)
async def add_new_todo(request: Request):
    user = await get_current_user(request)
    if user is None:
        return RedirectResponse(url="/auth", status_code=status.HTTP_302_FOUND)

    return templates.TemplateResponse("pages/user/add-todo.html", {"request": request, "user": user})


@router.post("/add-todo", response_class=HTMLResponse)
async def create_todo(request: Request,
                       title: str = Form(...), 
                       description: str = Form(...),
                       priority: int = Form(...), 
                       db: Session = Depends(get_db)):
    user = await get_current_user(request)
    if user is None:
        return RedirectResponse(url="/auth", status_code=status.HTTP_302_FOUND)

    todo_model = models.Todos()
    todo_model.title = title
    todo_model.description = description
    todo_model.priority = priority
    todo_model.complete = False
    todo_model.owner_id = user.get("id")

    db.add(todo_model)
    db.commit()

    return RedirectResponse(url="/todos", status_code=status.HTTP_302_FOUND)


@router.get("/edit-todo/{todo_id}", response_class=HTMLResponse)
async def edit_todo(request: Request, todo_id: int, db: Session = Depends(get_db)):

    user = await get_current_user(request)
    if user is None:
        return RedirectResponse(url="/auth", status_code=status.HTTP_302_FOUND)

    todo = db.query(models.Todos).filter(models.Todos.id == todo_id).first()

    return templates.TemplateResponse("pages/user/edit-todo.html", {"request": request, "todo": todo, "user": user})


@router.post("/edit-todo/{todo_id}", response_class=HTMLResponse)
async def edit_todo_commit(request: Request,
                            todo_id: int,
                            title: str = Form(...),
                            description: str = Form(...),
                            priority: int = Form(...),
                            db: Session = Depends(get_db)):

    user = await get_current_user(request)
    if user is None:
        return RedirectResponse(url="/auth", status_code=status.HTTP_302_FOUND)

    todo_model = db.query(models.Todos).filter(models.Todos.id == todo_id).first()

    todo_model.title = title
    todo_model.description = description
    todo_model.priority = priority

    db.add(todo_model)
    db.commit()

    return RedirectResponse(url="/todos", status_code=status.HTTP_302_FOUND)


@router.get("/delete/{todo_id}")
async def delete_todo(request: Request, todo_id: int, db: Session = Depends(get_db)):

    user = await get_current_user(request)
    if user is None:
        return RedirectResponse(url="/auth", status_code=status.HTTP_302_FOUND)

    todo_model = db.query(models.Todos).filter(models.Todos.id == todo_id)\
        .filter(models.Todos.owner_id == user.get("id")).first()

    if todo_model is None:
        return RedirectResponse(url="/todos", status_code=status.HTTP_302_FOUND)

    db.query(models.Todos).filter(models.Todos.id == todo_id).delete()

    db.commit()

    return RedirectResponse(url="/todos", status_code=status.HTTP_302_FOUND)


@router.get("/complete/{todo_id}", response_class=HTMLResponse)
async def complete_todo(request: Request, todo_id: int, db: Session = Depends(get_db)):

    user = await get_current_user(request)
    if user is None:
        return RedirectResponse(url="/auth", status_code=status.HTTP_302_FOUND)

    todo = db.query(models.Todos).filter(models.Todos.id == todo_id).first()

    todo.complete = not todo.complete

    db.add(todo)
    db.commit()

    return RedirectResponse(url="/todos", status_code=status.HTTP_302_FOUND)



@router.get("/access_denied", response_class=HTMLResponse, name="access_denied")
async def access_denied(request: Request):
    return HTMLResponse(content="Access Denied", status_code=status.HTTP_403_FORBIDDEN)