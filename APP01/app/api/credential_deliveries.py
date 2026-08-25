from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.credential_delivery_service import (
    CredentialDeliveryUnavailable,
    redeem_credential,
)


router = APIRouter(
    prefix="/credential-deliveries",
    tags=["Credential Delivery"],
)


class CredentialRedemptionRequest(BaseModel):
    retrieval_token: str


class CredentialRedemptionResponse(BaseModel):
    delivery_id: str
    employee_id: str
    temporary_password: str
    retrieved_at: str


@router.post(
    "/redeem",
    response_model=CredentialRedemptionResponse,
)
def redeem_one_time_credential(
    payload: CredentialRedemptionRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    try:
        result = redeem_credential(
            db=db,
            retrieval_token=payload.retrieval_token,
        )
        db.commit()

    except CredentialDeliveryUnavailable as exc:
        db.rollback()
        raise HTTPException(
            status_code=404,
            detail="Credential is unavailable.",
        ) from exc

    except Exception:
        db.rollback()
        raise

    # Prevent browsers and proxies from caching the password.
    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, private"
    )
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    return result
