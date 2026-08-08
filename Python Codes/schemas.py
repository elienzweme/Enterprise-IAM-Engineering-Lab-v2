from pydantic import BaseModel, ConfigDict
from typing import Optional


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
    email: Optional[str]
    department: Optional[str]
    job_title: Optional[str]
    manager: Optional[str]
    employment_status: str
    source_system: str