from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Employee(Base):
    __tablename__ = "employees"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    employee_id: Mapped[str] = mapped_column(String(50), unique=True, index=True)

    first_name: Mapped[str] = mapped_column(String(100))
    last_name: Mapped[str] = mapped_column(String(100))

    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    department: Mapped[str | None] = mapped_column(String(100), nullable=True)
    job_title: Mapped[str | None] = mapped_column(String(150), nullable=True)
    manager: Mapped[str | None] = mapped_column(String(150), nullable=True)

    manager_employee_id: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
        index=True
    )

    employment_status: Mapped[str] = mapped_column(
        String(50),
        default="Active"
    )

    source_system: Mapped[str] = mapped_column(
        String(50),
        default="OrangeHRM"
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )


class IdentityRequest(Base):
    __tablename__ = "identity_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    request_id: Mapped[str] = mapped_column(
        String(50),
        unique=True,
        index=True
    )

    employee_id: Mapped[str] = mapped_column(
        String(50),
        index=True
    )

    action: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(
        String(50),
        default="Pending"
    )

    jira_issue_key: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True
    )

    requested_by: Mapped[str | None] = mapped_column(
        String(150),
        nullable=True
    )

    approved_by: Mapped[str | None] = mapped_column(
        String(150),
        nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    request_id: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
        index=True
    )

    employee_id: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
        index=True
    )

    event_type: Mapped[str] = mapped_column(String(100))
    system: Mapped[str] = mapped_column(String(100))
    result: Mapped[str] = mapped_column(String(50))

    details: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow
    )