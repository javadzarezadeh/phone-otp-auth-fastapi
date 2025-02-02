import uuid
from typing import Any

from sqlmodel import Session, select

from app.core.security import get_password_hash, verify_password
from app.models import Item, ItemCreate, User, UserCreate, UserUpdate


def create_user(*, session: Session, user_create: UserCreate) -> User:
    db_obj = User.model_validate(user_create)
    session.add(db_obj)
    session.commit()
    session.refresh(db_obj)
    return db_obj


def update_user(*, session: Session, db_user: User, user_in: UserUpdate) -> Any:
    user_data = user_in.model_dump(exclude_unset=True)
    extra_data = {}
    if "otp" in user_data and user_data["otp"] is not None:
        otp = user_data["otp"]
        hashed_otp = get_password_hash(otp)
        extra_data["hashed_otp"] = hashed_otp
    elif "otp" in user_data and user_data["otp"] is None:
        extra_data["hashed_otp"] = None
    db_user.sqlmodel_update(user_data, update=extra_data)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user


def get_user_by_phone_number(*, session: Session, phone_number: str) -> User | None:
    statement = select(User).where(User.phone_number == phone_number)
    session_user = session.exec(statement).first()
    return session_user


def authenticate(*, session: Session, phone_number: str, otp: str) -> User | None:
    db_user = get_user_by_phone_number(session=session, phone_number=phone_number)
    if not db_user:
        return None
    if not verify_password(otp, db_user.hashed_otp):
        return None
    return db_user


def create_item(*, session: Session, item_in: ItemCreate, owner_id: uuid.UUID) -> Item:
    db_item = Item.model_validate(item_in, update={"owner_id": owner_id})
    session.add(db_item)
    session.commit()
    session.refresh(db_item)
    return db_item
