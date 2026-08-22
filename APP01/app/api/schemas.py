from typing import Optional

from pydantic import BaseModel, ConfigDict


# ============================================================
# EMPLOYEE SCHEMAS
# ============================================================

class EmployeeCreate(BaseModel):
    employee_id: str
    first_name: str
    last_name: str
    email: Optional[str] = None
    department: Optional[str] = None
    job_title: Optional[str] = None
    manager: Optional[str] = None
    employment_status: str = "Active"
    source_system: str = "Manual"


class EmployeeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    employee_id: str
    first_name: str
    last_name: str
    email: Optional[str] = None
    department: Optional[str] = None
    job_title: Optional[str] = None
    manager: Optional[str] = None
    employment_status: str
    source_system: str


# ============================================================
# IDENTITY REQUEST APPROVAL SCHEMA
# ============================================================

class ApprovalRequest(BaseModel):
    """
    Request body used when approving an identity request.

    Example:
    {
        "approved_by": "iam.admin"
    }
    """

    approved_by: str


# ============================================================
# IDENTITY REQUEST REJECTION SCHEMA
# ============================================================

class RejectionRequest(BaseModel):
    """
    Request body used when rejecting an identity request.

    Example:
    {
        "rejected_by": "iam.admin",
        "reason": "Incorrect department assignment"
    }
    """

    rejected_by: str
    reason: Optional[str] = None
