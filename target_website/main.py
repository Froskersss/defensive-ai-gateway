"""
main.py: FastAPI Application Entry Point
"""
from fastapi import FastAPI, HTTPException, Query, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from database import get_db
from models import User, Employee, WeaponProject, seed_database
from schemas import UserSignup, UserLogin

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
app = FastAPI(title="Aegis Dynamics Internal Portal", version="5.1")

templates = Jinja2Templates(directory="templates")

@app.on_event("startup")
def startup_event():
    try:
        seed_database()
    except Exception as e:
        print(f"[-] Database connection error: {e}")

@app.get("/", response_class=HTMLResponse)
def serve_portal(request: Request):
    # Pass request as the first positional argument for newer Starlette versions
    return templates.TemplateResponse(request, "index.html", {})

@app.post("/api/v1/signup")
def signup(user_data: UserSignup, db: Session = Depends(get_db)):
    existing = db.query(User).filter((User.username == user_data.username) | (User.email == user_data.email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username or email already registered.")
    
    hashed_pwd = pwd_context.hash(user_data.password)
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_pwd,
        clearance="CONFIDENTIAL"
    )
    db.add(new_user)
    db.commit()
    return {"status": "success", "message": "Account created successfully. You can now log in."}

@app.post("/api/v1/login")
def login(creds: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == creds.username).first()
    if not user or not pwd_context.verify(creds.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    return {"status": "success", "username": user.username, "clearance": user.clearance, "message": "Authentication successful."}

@app.get("/api/v1/employees")
def get_employees(limit: int = 50, db: Session = Depends(get_db)):
    employees = db.query(Employee).limit(limit).all()
    return {"count": len(employees), "data": [{"code": e.emp_code, "name": e.full_name, "department": e.department, "clearance": e.clearance_level} for e in employees]}

@app.get("/api/v1/search")
def search_weapons(q: str = Query("", description="Search keyword"), db: Session = Depends(get_db)):
    results = db.query(WeaponProject).filter(
        WeaponProject.project_codename.like(f"%{q}%") | WeaponProject.classification_notes.like(f"%{q}%")
    ).all()
    return {
        "query": q,
        "matches_found": len(results),
        "results": [{"codename": r.project_codename, "category": r.category, "status": r.status, "notes": r.classification_notes} for r in results]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8002, reload=True)