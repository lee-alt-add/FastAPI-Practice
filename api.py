from typing import List
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import select, Session, SQLModel, and_
from database import User, Expense, Income, engine, get_session, update_db
from security import get_session, get_current_user, create_access_token, pwd_context
from pydantic import BaseModel


app = FastAPI()

# Create tables on startup
@app.on_event("startup")
def startup():
    SQLModel.metadata.create_all(engine)

class item_schema(BaseModel):
    description: str
    amount: float


@app.post("/register")
def register(username: str, password: str, session: Session =Depends(get_session)):
    hashed_password = pwd_context.hash(password)
    user = User(username=username, hashed_password=hashed_password)
    session.add(user)
    session.commit()
    return {"message": "User created"}

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == form_data.username)).first()
    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/expense", response_model=Expense)
def add_expense(data: item_schema, current_user: User=Depends(get_current_user), session: Session=Depends(get_session)):
    new_expense = Expense(
        description=data.description, 
        amount=data.amount, 
        owner_id=current_user.id
        )
    update_db(session, new_expense)
    return new_expense

@app.get("/expense", response_model=List[Expense])
def get_all_expenses(current_user: User = Depends(get_current_user), session: Session=Depends(get_session)):
    expenses = session.exec(select(Expense).where(Expense.owner_id == current_user.id)).all()
    return expenses

@app.delete("/expense/{expense_id}", response_model=Expense)
def delete_expense(expense_id: int, current_user: User= Depends(get_current_user), session: Session= Depends(get_session)):
    expense = session.exec(
        select(Expense)
        .where(and_(Expense.id == expense_id, Expense.owner_id == current_user.id))
        ).first()
    if not expense:
        raise HTTPException(status_code=404, detail="Expense not found")
    update_db(session, expense, refresh=False, delete=True)
    return expense

@app.put("/expense/{expense_id}", response_model=Expense)
def update_expense(expense_id: int, data: item_schema, current_user: User = Depends(get_current_user), session: Session=Depends(get_session)):
    expense = session.exec(
        select(Expense)        
        .where(and_(Expense.id == expense_id, Expense.owner_id == current_user.id))
        ).first()
    if not expense:
        raise HTTPException(status_code=404, detail="Expense not found")
    
    expense.description = data.description
    expense.amount = data.amount
    update_db(session, expense)
    return expense

@app.post("/income", response_model=Income)
def add_income(data: item_schema, current_user: User=Depends(get_current_user), session: Session=Depends(get_session)):
    new_income = Income(
        description=data.description, 
        amount=data.amount, 
        owner_id=current_user.id
        )
    update_db(session, new_income)
    return new_income

@app.get("/income", response_model=List[Income])
def get_all_income(current_user: User = Depends(get_current_user), session: Session=Depends(get_session)):
    income = session.exec(select(Income).where(Income.owner_id == current_user.id)).all()
    return income

@app.delete("/income/{income_id}", response_model=Income)
def delete_income(income_id: int, current_user: User= Depends(get_current_user), session: Session= Depends(get_session)):
    income_to_remove = session.exec(
        select(Income)
        .where(and_(Income.id == income_id, Income.owner_id == current_user.id))
        ).first()
    if not income_to_remove:
        raise HTTPException(status_code=404, detail="Income not found")
    update_db(session, income_to_remove, refresh=False, delete=True)
    return income_to_remove

@app.put("/income/{income_id}", response_model=Income)
def update_income(income_id: int, data: item_schema, current_user: User = Depends(get_current_user), session: Session=Depends(get_session)):
    income = session.exec(
        select(Income)        
        .where(and_(Income.id == income_id, Income.owner_id == current_user.id))
        ).first()
    if not income:
        raise HTTPException(status_code=404, detail="Income not found")
    
    income.description = data.description
    income.amount = data.amount
    update_db(session, income)
    return income