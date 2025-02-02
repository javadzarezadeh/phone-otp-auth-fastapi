from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm

from app import crud
from app.api.deps import CurrentUser, SessionDep
from app.core import security
from app.core.config import settings
from app.models import Message, Token, UserCreate, UserPublic, UserUpdate
from app.utils import (
    generate_otp,
    send_otp,
)

router = APIRouter(tags=["login"])

OTP_EXPIRE_MINUTES = 5


@router.post("/login/request-otp")
def request_otp(session: SessionDep, phone_number: str) -> Message:
    """
    Generate and send OTP to the provided phone number.
    """
    user = crud.get_user_by_phone_number(session=session, phone_number=phone_number)
    if not user:
        user = crud.create_user(
            session=session, user_create=UserCreate(phone_number=phone_number)
        )

    otp = generate_otp()

    delta = timedelta(minutes=OTP_EXPIRE_MINUTES)
    now = datetime.now(timezone.utc)
    otp_expires_at = now + delta

    crud.update_user(
        session=session,
        db_user=user,
        user_in=UserUpdate(otp=otp, otp_expires_at=otp_expires_at),
    )

    send_otp(phone_number, otp)

    if user.is_superuser:
        return Message(message=f"OTP: {otp}")

    return Message(message="OTP sent successfully.")


@router.post("/login/access-token")
def login_access_token(
    session: SessionDep, form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> Token:
    """
    OAuth2 compatible token login, get an access token for future requests
    """
    user = crud.authenticate(
        session=session, phone_number=form_data.username, otp=form_data.password
    )
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect phone number or OTP")
    elif not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    crud.update_user(
        session=session, db_user=user, user_in=UserUpdate(otp=None, otp_expires_at=None)
    )
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return Token(
        access_token=security.create_access_token(
            user.id, expires_delta=access_token_expires
        )
    )


@router.post("/login/test-token", response_model=UserPublic)
def test_token(current_user: CurrentUser) -> Any:
    """
    Test access token
    """
    return current_user
