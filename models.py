"""Validated request models for clinic staff, patients, and appointments."""

import re
from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class LoginRequest(BaseModel):
    """Credentials submitted by an employee on the clinic sign-in screen."""

    login: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class EmployeeCreate(BaseModel):
    """Staff details entered by an administrator when registering an employee."""

    full_name: str = Field(min_length=3, max_length=160)
    specialty: str = Field(min_length=2, max_length=120)
    employee_iin: str = Field(min_length=12, max_length=12)
    cabinet: int | Literal["Регистратура"]
    role: Literal["Doctor", "Registrar"]
    password: str = Field(min_length=8, max_length=128)

    @field_validator("employee_iin")
    @classmethod
    def validate_employee_iin(cls, value: str) -> str:
        """Validate the unique 12-digit identity number used to distinguish staff."""
        normalized = value.strip()
        if not re.fullmatch(r"\d{12}", normalized):
            raise ValueError("ИИН сотрудника должен содержать ровно 12 цифр.")
        return normalized

    @model_validator(mode="after")
    def validate_cabinet_for_doctor(self) -> "EmployeeCreate":
        """Require a numbered doctor room or the fixed reception department name."""
        if self.role == "Doctor" and (
            not isinstance(self.cabinet, int) or not 1 <= self.cabinet <= 9999
        ):
            raise ValueError("Для врача необходимо указать кабинет.")
        if self.role == "Registrar" and self.cabinet != "Регистратура":
            raise ValueError("Для регистратора кабинет фиксирован: «Регистратура».")
        return self


class EmployeeIdentityUpdate(BaseModel):
    """A staff identity number added to an account imported from the older system."""

    employee_iin: str = Field(min_length=12, max_length=12)

    @field_validator("employee_iin")
    @classmethod
    def validate_employee_iin(cls, value: str) -> str:
        """Validate the unique 12-digit identity number before it is saved."""
        normalized = value.strip()
        if not re.fullmatch(r"\d{12}", normalized):
            raise ValueError("ИИН сотрудника должен содержать ровно 12 цифр.")
        return normalized


class PatientCreate(BaseModel):
    """Patient information collected at the clinic reception desk."""

    full_name: str = Field(min_length=3, max_length=160)
    birth_date: str
    phone: str = Field(min_length=10, max_length=20)
    iin: str = Field(min_length=12, max_length=12)

    @field_validator("iin")
    @classmethod
    def validate_iin(cls, value: str) -> str:
        """Ensure the national identification number contains exactly 12 digits."""
        normalized = value.strip()
        if not normalized.isdigit() or len(normalized) != 12:
            raise ValueError("ИИН должен содержать ровно 12 цифр.")
        return normalized

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, value: str) -> str:
        """Normalize phone formatting before uniqueness checks in the database."""
        digits = "".join(character for character in value if character.isdigit())
        if not 10 <= len(digits) <= 15:
            raise ValueError("Укажите телефон, содержащий от 10 до 15 цифр.")
        return f"+{digits}"

    @field_validator("birth_date")
    @classmethod
    def validate_birth_date(cls, value: str) -> str:
        """Accept only a real ISO calendar date for the patient's record."""
        try:
            parsed = date.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("Укажите дату рождения в формате ГГГГ-ММ-ДД.") from exc
        if parsed > date.today():
            raise ValueError("Дата рождения не может быть позже сегодняшнего дня.")
        return parsed.isoformat()


class AppointmentCreate(BaseModel):
    """A reception appointment request that links a patient to a doctor."""

    patient_id: int = Field(gt=0)
    doctor_id: int = Field(gt=0)
    appointment_time: str = Field(min_length=16, max_length=32)

    @field_validator("appointment_time")
    @classmethod
    def validate_appointment_time(cls, value: str) -> str:
        """Normalize browser date-time input for stable collision detection."""
        try:
            appointment = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("Укажите корректные дату и время приёма.") from exc
        if appointment.tzinfo is not None:
            appointment = appointment.replace(tzinfo=None)
        return appointment.strftime("%Y-%m-%d %H:%M")


class AppointmentStatusUpdate(BaseModel):
    """Status selected by a doctor while documenting an appointment."""

    status: Literal["Приём завершён", "Отменён"]


class MedicalDocumentCreate(BaseModel):
    """An electronic prescription or referral prepared during a consultation."""

    patient_id: int = Field(gt=0)
    partner_id: int = Field(gt=0)
    document_type: Literal["Рецепт", "Направление"]
    details: str = Field(min_length=3, max_length=2000)


class ClinicServiceCreate(BaseModel):
    """Paid clinic service shown to doctors and maintained by an administrator."""

    name: str = Field(min_length=2, max_length=160)
    specialty: str = Field(default="", max_length=120)
    price_kzt: int = Field(gt=0, le=100_000_000)
    description: str = Field(default="", max_length=1000)

    @field_validator("name", "specialty", "description")
    @classmethod
    def strip_text(cls, value: str) -> str:
        """Normalize user-entered price-list text before persistence."""
        return value.strip()
