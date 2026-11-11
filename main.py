"""FastAPI application and role-protected routes for the private clinic."""

import logging
import os
import secrets
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Callable

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool
from starlette.middleware.sessions import SessionMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from database import get_db, init_db
from models import (
    AppointmentCreate,
    AppointmentStatusUpdate,
    ClinicServiceCreate,
    EmployeeCreate,
    EmployeeIdentityUpdate,
    LoginRequest,
    MedicalDocumentCreate,
    PatientCreate,
)
from services import ClinicService
from partner_portal.main import router as partner_portal_router

logger = logging.getLogger(__name__)
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))
PARTNER_PORTAL_BASE_PATH = "/partner"
WORKSPACES = {"admin", "register", "doctor"}


class WorkspaceSessionMiddleware:
    """Give each role workspace an isolated signed-session cookie and shared routes."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope["path"]
        parts = path.split("/", 2)
        workspace = parts[1] if len(parts) > 1 and parts[1] in WORKSPACES else None
        if workspace is None:
            await self.app(scope, receive, send)
            return

        scoped_cookie = f"clinic_{workspace}_session"
        headers = list(scope["headers"])
        cookie_values = [
            value.decode("latin-1")
            for name, value in headers
            if name.lower() == b"cookie"
        ]
        cookie_pairs = [
            pair.strip()
            for value in cookie_values
            for pair in value.split(";")
            if pair.strip()
            and pair.strip().split("=", 1)[0] not in {"clinic_session", scoped_cookie}
        ]
        scoped_value = next(
            (
                pair.split("=", 1)[1]
                for value in cookie_values
                for pair in value.split(";")
                if pair.strip().startswith(f"{scoped_cookie}=")
            ),
            None,
        )
        if scoped_value is not None:
            cookie_pairs.append(f"clinic_session={scoped_value}")
        headers = [(name, value) for name, value in headers if name.lower() != b"cookie"]
        if cookie_pairs:
            headers.append((b"cookie", "; ".join(cookie_pairs).encode("latin-1")))

        rewritten_path = "/" + parts[2] if len(parts) > 2 and parts[2] else "/"
        scope = dict(scope)
        scope["path"] = rewritten_path
        scope["raw_path"] = rewritten_path.encode("utf-8")
        scope["headers"] = headers
        scope.setdefault("state", {})["workspace"] = workspace

        async def send_with_workspace_cookie(message: Message) -> None:
            if message["type"] == "http.response.start":
                rewritten_headers = []
                for name, value in message.get("headers", []):
                    if name.lower() == b"set-cookie" and value.startswith(
                        b"clinic_session="
                    ):
                        cookie = value.decode("latin-1")
                        cookie = cookie.replace(
                            "clinic_session=", f"{scoped_cookie}=", 1
                        )
                        cookie = cookie.replace("path=/", f"path=/{workspace}", 1)
                        cookie = cookie.replace("Path=/", f"Path=/{workspace}", 1)
                        value = cookie.encode("latin-1")
                    rewritten_headers.append((name, value))
                message = {**message, "headers": rewritten_headers}
            await send(message)

        await self.app(scope, receive, send_with_workspace_cookie)


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Initialize SQLite before serving clinic requests and release app resources."""
    await run_in_threadpool(init_db)
    yield


app = FastAPI(title="ИС «Частная клиника»", lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("CLINIC_SESSION_SECRET", secrets.token_urlsafe(32)),
    session_cookie="clinic_session",
    max_age=8 * 60 * 60,
    same_site="strict",
    https_only=False,
)
app.add_middleware(WorkspaceSessionMiddleware)
app.include_router(partner_portal_router, prefix=PARTNER_PORTAL_BASE_PATH)


@app.exception_handler(RequestValidationError)
async def handle_invalid_form(
    request: Request, exception: RequestValidationError
) -> JSONResponse:
    """Translate invalid fields to clear Russian form guidance for the user."""
    field_names = {
        "full_name": "ФИО",
        "specialty": "специальность или отдел",
        "employee_iin": "ИИН сотрудника",
        "cabinet": "кабинет или отдел",
        "role": "должность",
        "password": "пароль",
        "phone": "телефон",
        "iin": "ИИН пациента",
        "birth_date": "дата рождения",
        "patient_id": "пациент",
        "doctor_id": "врач",
        "appointment_time": "дата и время приёма",
        "partner_id": "медицинская организация",
        "document_type": "вид документа",
        "details": "назначение или цель направления",
    }
    errors = exception.errors()
    fields = list(
        dict.fromkeys(
            field_names.get(str(error["loc"][-1]), str(error["loc"][-1]))
            for error in errors
            if error.get("loc") and error["loc"][-1] != "body"
        )
    )
    root_messages = [
        str(error.get("msg", "")).removeprefix("Value error, ")
        for error in errors
        if not error.get("loc") or error["loc"][-1] == "body"
    ]
    if fields:
        detail = f"Проверьте поля: {', '.join(fields)}."
    elif root_messages:
        detail = "Проверьте данные: " + "; ".join(root_messages)
    else:
        detail = "Проверьте заполнение обязательных полей."
    logger.debug(
        "Форма клиники отклонена: method=%s, fields=%s",
        request.method,
        ", ".join(fields) or "неизвестно",
    )
    return JSONResponse(status_code=422, content={"detail": detail})


def roles_required(*allowed_roles: str) -> Callable[..., Any]:
    """Build a dependency that enforces the requested clinic roles on each route."""

    async def verify_role(
        current_user: dict[str, Any] = Depends(get_current_user),
    ) -> dict[str, Any]:
        if current_user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail="У вашей должности нет доступа к этому разделу.",
            )
        return current_user

    return verify_role


async def get_current_user(
    request: Request,
    connection: sqlite3.Connection = Depends(get_db),
) -> dict[str, Any]:
    """Resolve the signed browser session to an active employee account."""
    try:
        employee_id = request.session.get("employee_id")
        if employee_id is None:
            raise HTTPException(
                status_code=401, detail="Войдите в систему, чтобы продолжить."
            )
        employee = await run_in_threadpool(
            ClinicService.get_employee, connection, int(employee_id)
        )
        if employee is None:
            request.session.clear()
            raise HTTPException(
                status_code=401, detail="Сеанс завершён. Войдите в систему повторно."
            )
        return employee
    except HTTPException:
        raise
    except (TypeError, ValueError) as exc:
        request.session.clear()
        raise HTTPException(
            status_code=401, detail="Сеанс завершён. Войдите в систему повторно."
        ) from exc
    except sqlite3.Error as exc:
        logger.exception("Не удалось подтвердить сеанс сотрудника.")
        raise HTTPException(
            status_code=503,
            detail="Не удалось проверить доступ. Повторите попытку позже.",
        ) from exc


def _service_error(exc: sqlite3.Error) -> HTTPException:
    """Log storage failures and translate them into a clear clinic-facing message."""
    logger.exception("Ошибка при работе с данными клиники.", exc_info=exc)
    return HTTPException(
        status_code=503,
        detail="Не удалось выполнить операцию. Повторите попытку позже.",
    )


@app.get("/", response_class=HTMLResponse)
async def read_dashboard(
    request: Request,
    connection: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    """Render the sign-in screen or the clinic dashboard for the active employee."""
    try:
        employee_id = request.session.get("employee_id")
        user = None
        doctors: list[dict[str, Any]] = []
        schedule: list[dict[str, Any]] = []
        employees: list[dict[str, Any]] = []
        partners: list[dict[str, Any]] = []
        patient_registry: dict[str, Any] = {
            "items": [],
            "total": 0,
            "page": 1,
            "page_size": 10,
        }
        medical_documents: list[dict[str, Any]] = []
        price_list: list[dict[str, Any]] = []
        if employee_id is not None:
            user = await run_in_threadpool(
                ClinicService.get_employee, connection, int(employee_id)
            )
            if user is None:
                request.session.clear()
            else:
                role = user["role"]
                if role in {"Admin", "Registrar"}:
                    doctors = await run_in_threadpool(
                        ClinicService.get_doctors, connection
                    )
                if role == "Doctor":
                    schedule = await run_in_threadpool(
                        ClinicService.get_schedule, connection, user["id"]
                    )
                    partners = await run_in_threadpool(
                        ClinicService.get_partners, connection
                    )
                elif role in {"Admin", "Registrar"}:
                    schedule = await run_in_threadpool(
                        ClinicService.get_schedule, connection
                    )
                    patient_registry = await run_in_threadpool(
                        ClinicService.get_patient_registry_page,
                        connection,
                    )
                if role == "Admin":
                    employees = await run_in_threadpool(
                        ClinicService.get_all_employees, connection
                    )
                    partners = await run_in_threadpool(
                        ClinicService.get_partners, connection
                    )
                    medical_documents = await run_in_threadpool(
                        ClinicService.get_medical_documents, connection
                    )
                    price_list = await run_in_threadpool(
                        ClinicService.get_clinic_services, connection
                    )
                elif role == "Doctor":
                    medical_documents = await run_in_threadpool(
                        ClinicService.get_medical_documents, connection, user["id"]
                    )
                    price_list = await run_in_threadpool(
                        ClinicService.get_clinic_services,
                        connection,
                        user["specialty"],
                    )
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "user": user,
                "doctors": doctors,
                "schedule": schedule,
                "employees": employees,
                "partners": partners,
                "patient_registry": patient_registry,
                "medical_documents": medical_documents,
                "price_list": price_list,
                "workspace": getattr(request.state, "workspace", None),
                "partner_portal_url": os.environ.get(
                    "PARTNER_PORTAL_URL", f"{PARTNER_PORTAL_BASE_PATH}/"
                ),
            },
        )
    except sqlite3.Error as exc:
        logger.exception("Не удалось подготовить рабочее место клиники.")
        raise HTTPException(
            status_code=503,
            detail="Не удалось загрузить рабочее место. Повторите попытку позже.",
        ) from exc


@app.post("/auth/login")
async def login(
    data: LoginRequest,
    request: Request,
    connection: sqlite3.Connection = Depends(get_db),
) -> dict[str, Any]:
    """Authenticate an employee and start a protected, signed browser session."""
    try:
        employee = await run_in_threadpool(
            ClinicService.authenticate, connection, data.login, data.password
        )
        workspace = getattr(request.state, "workspace", None)
        allowed_workspace_roles = {
            "admin": {"Admin"},
            "register": {"Admin", "Registrar"},
            "doctor": {"Admin", "Doctor"},
        }
        if workspace and employee["role"] not in allowed_workspace_roles[workspace]:
            raise HTTPException(
                status_code=403,
                detail="Эта учётная запись не предназначена для выбранного рабочего места.",
            )
        request.session.clear()
        request.session["employee_id"] = employee["id"]
        return employee
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except sqlite3.Error as exc:
        raise _service_error(exc) from exc


@app.post("/auth/logout")
async def logout(request: Request) -> dict[str, str]:
    """End the current browser session when the employee signs out."""
    try:
        request.session.clear()
        return {"message": "Сеанс завершён."}
    except (AttributeError, RuntimeError) as exc:
        logger.exception("Не удалось завершить сеанс сотрудника.")
        raise HTTPException(
            status_code=400, detail="Не удалось завершить сеанс."
        ) from exc


@app.get("/api/me")
async def current_session(
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """Return the active employee profile used to personalize the dashboard."""
    try:
        return current_user
    except (KeyError, TypeError) as exc:
        logger.exception("Не удалось подготовить профиль сотрудника.")
        raise HTTPException(
            status_code=401, detail="Войдите в систему, чтобы продолжить."
        ) from exc


@app.get("/api/staff")
async def get_staff(
    connection: sqlite3.Connection = Depends(get_db),
    _: dict[str, Any] = Depends(roles_required("Admin")),
) -> list[dict[str, Any]]:
    """List clinic employees for administrators managing staff access."""
    try:
        return await run_in_threadpool(ClinicService.get_all_employees, connection)
    except sqlite3.Error as exc:
        raise _service_error(exc) from exc


@app.post("/api/staff")
async def create_staff(
    employee: EmployeeCreate,
    connection: sqlite3.Connection = Depends(get_db),
    _: dict[str, Any] = Depends(roles_required("Admin")),
) -> dict[str, Any]:
    """Register a new doctor or registrar from the administrator's panel."""
    try:
        return await run_in_threadpool(
            ClinicService.add_employee, connection, employee
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except sqlite3.Error as exc:
        raise _service_error(exc) from exc


@app.patch("/api/staff/{employee_id}/identity")
async def update_staff_identity(
    employee_id: int,
    identity: EmployeeIdentityUpdate,
    connection: sqlite3.Connection = Depends(get_db),
    _: dict[str, Any] = Depends(roles_required("Admin")),
) -> dict[str, Any]:
    """Add a unique IIN to a staff record created before identity checks existed."""
    try:
        return await run_in_threadpool(
            ClinicService.update_employee_iin,
            connection,
            employee_id,
            identity,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except sqlite3.Error as exc:
        raise _service_error(exc) from exc


@app.patch("/api/employees/{employee_id}/iin")
async def update_employee_iin(
    employee_id: int,
    identity: EmployeeIdentityUpdate,
    connection: sqlite3.Connection = Depends(get_db),
    _: dict[str, Any] = Depends(roles_required("Admin")),
) -> dict[str, Any]:
    """Set or change an employee IIN through the current personnel interface."""
    try:
        return await run_in_threadpool(
            ClinicService.update_employee_iin,
            connection,
            employee_id,
            identity,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except sqlite3.Error as exc:
        raise _service_error(exc) from exc


@app.delete("/api/staff/{employee_id}")
async def delete_staff(
    employee_id: int,
    connection: sqlite3.Connection = Depends(get_db),
    current_user: dict[str, Any] = Depends(roles_required("Admin")),
) -> dict[str, int]:
    """Delete an unused employee account while retaining all medical history."""
    try:
        return await run_in_threadpool(
            ClinicService.delete_employee,
            connection,
            employee_id,
            current_user["id"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except sqlite3.Error as exc:
        raise _service_error(exc) from exc


@app.delete("/api/employees/{employee_id}")
async def delete_employee(
    employee_id: int,
    connection: sqlite3.Connection = Depends(get_db),
    current_user: dict[str, Any] = Depends(roles_required("Admin")),
) -> dict[str, int]:
    """Remove an employee through the personnel interface without losing history."""
    try:
        return await run_in_threadpool(
            ClinicService.delete_employee,
            connection,
            employee_id,
            current_user["id"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except sqlite3.Error as exc:
        raise _service_error(exc) from exc


@app.get("/api/patients")
async def get_patients(
    connection: sqlite3.Connection = Depends(get_db),
    current_user: dict[str, Any] = Depends(
        roles_required("Admin", "Registrar", "Doctor")
    ),
) -> list[dict[str, Any]]:
    """Load clinic patients for the permitted reception and medical workflows."""
    try:
        doctor_id = (
            current_user["id"] if current_user["role"] == "Doctor" else None
        )
        return await run_in_threadpool(
            ClinicService.get_all_patients, connection, doctor_id
        )
    except sqlite3.Error as exc:
        raise _service_error(exc) from exc


@app.post("/api/patients")
async def create_patient(
    patient: PatientCreate,
    connection: sqlite3.Connection = Depends(get_db),
    _: dict[str, Any] = Depends(roles_required("Admin", "Registrar")),
) -> dict[str, Any]:
    """Create a patient chart and return its automatically issued card number."""
    try:
        return await run_in_threadpool(
            ClinicService.add_patient, connection, patient
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except sqlite3.Error as exc:
        raise _service_error(exc) from exc


@app.get("/api/patient-search")
async def search_patient_options(
    search: str = Query(default="", max_length=120),
    connection: sqlite3.Connection = Depends(get_db),
    current_user: dict[str, Any] = Depends(
        roles_required("Admin", "Registrar", "Doctor")
    ),
) -> list[dict[str, Any]]:
    """Find up to ten eligible patient cards for appointment/document forms."""
    try:
        doctor_id = current_user["id"] if current_user["role"] == "Doctor" else None
        return await run_in_threadpool(
            ClinicService.search_patients,
            connection,
            search,
            doctor_id,
            10,
        )
    except sqlite3.Error as exc:
        raise _service_error(exc) from exc


@app.get("/api/doctors")
async def get_doctors(
    connection: sqlite3.Connection = Depends(get_db),
    _: dict[str, Any] = Depends(roles_required("Admin", "Registrar")),
) -> list[dict[str, Any]]:
    """Provide the reception desk with the doctors available for appointments."""
    try:
        return await run_in_threadpool(ClinicService.get_doctors, connection)
    except sqlite3.Error as exc:
        raise _service_error(exc) from exc


@app.get("/api/appointments")
async def get_appointments(
    connection: sqlite3.Connection = Depends(get_db),
    current_user: dict[str, Any] = Depends(
        roles_required("Admin", "Registrar", "Doctor")
    ),
) -> list[dict[str, Any]]:
    """Return the complete journal to reception or only assigned visits to a doctor."""
    try:
        doctor_id = current_user["id"] if current_user["role"] == "Doctor" else None
        return await run_in_threadpool(
            ClinicService.get_schedule, connection, doctor_id
        )
    except sqlite3.Error as exc:
        raise _service_error(exc) from exc


@app.post("/api/appointments")
async def create_appointment(
    appointment: AppointmentCreate,
    connection: sqlite3.Connection = Depends(get_db),
    _: dict[str, Any] = Depends(roles_required("Admin", "Registrar")),
) -> dict[str, Any]:
    """Book a patient with the selected doctor from the reception desk."""
    try:
        return await run_in_threadpool(
            ClinicService.create_appointment, connection, appointment
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except sqlite3.Error as exc:
        raise _service_error(exc) from exc


@app.patch("/api/appointments/{appointment_id}")
async def update_appointment(
    appointment_id: int,
    update: AppointmentStatusUpdate,
    connection: sqlite3.Connection = Depends(get_db),
    current_user: dict[str, Any] = Depends(roles_required("Admin", "Doctor")),
) -> dict[str, Any]:
    """Record a visit outcome for its assigned doctor or a clinic administrator."""
    try:
        doctor_id = (
            current_user["id"] if current_user["role"] == "Doctor" else None
        )
        return await run_in_threadpool(
            ClinicService.update_appointment_status,
            connection,
            appointment_id,
            update.status,
            doctor_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except sqlite3.Error as exc:
        raise _service_error(exc) from exc


@app.get("/api/partners")
async def get_partners(
    connection: sqlite3.Connection = Depends(get_db),
    _: dict[str, Any] = Depends(roles_required("Admin", "Doctor")),
) -> list[dict[str, Any]]:
    """List the pharmacy and hospital destinations available to clinicians."""
    try:
        return await run_in_threadpool(ClinicService.get_partners, connection)
    except sqlite3.Error as exc:
        raise _service_error(exc) from exc


@app.get("/api/live-data")
async def get_live_data(
    response: Response,
    registry_page: int = Query(default=1, ge=1),
    registry_search: str = Query(default="", max_length=120),
    registry_status: str = Query(default="", max_length=40),
    connection: sqlite3.Connection = Depends(get_db),
    current_user: dict[str, Any] = Depends(
        roles_required("Admin", "Registrar", "Doctor")
    ),
) -> dict[str, Any]:
    """Return only the current role's live data for partial dashboard refreshes."""
    try:
        response.headers["Cache-Control"] = "no-store"
        allowed_statuses = {
            "",
            "Ожидает записи",
            "Запланирован",
            "Приём завершён",
            "Отменён",
        }
        if registry_status not in allowed_statuses:
            raise HTTPException(
                status_code=422, detail="Выбран неизвестный статус приёма."
            )
        role = current_user["role"]
        doctor_id = current_user["id"] if role == "Doctor" else None
        payload: dict[str, Any] = {
            "appointments": await run_in_threadpool(
                ClinicService.get_schedule, connection, doctor_id
            ),
        }
        if role in {"Admin", "Registrar"}:
            payload["doctors"] = await run_in_threadpool(
                ClinicService.get_doctors, connection
            )
            patient_registry = await run_in_threadpool(
                ClinicService.get_patient_registry_page,
                connection,
                registry_page,
                10,
                registry_search,
                registry_status,
            )
            total_pages = max(
                1,
                (patient_registry["total"] + patient_registry["page_size"] - 1)
                // patient_registry["page_size"],
            )
            if registry_page > total_pages:
                patient_registry = await run_in_threadpool(
                    ClinicService.get_patient_registry_page,
                    connection,
                    total_pages,
                    10,
                    registry_search,
                    registry_status,
                )
            payload["patient_registry"] = patient_registry
        if role in {"Admin", "Doctor"}:
            payload["price_list"] = await run_in_threadpool(
                ClinicService.get_clinic_services,
                connection,
                None if role == "Admin" else current_user["specialty"],
            )
            payload["medical_documents"] = await run_in_threadpool(
                ClinicService.get_medical_documents, connection, doctor_id
            )
        if role == "Admin":
            payload["employees"] = await run_in_threadpool(
                ClinicService.get_all_employees, connection
            )
        return payload
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except sqlite3.Error as exc:
        raise _service_error(exc) from exc


@app.get("/api/prices")
async def get_price_list(
    connection: sqlite3.Connection = Depends(get_db),
    current_user: dict[str, Any] = Depends(roles_required("Admin", "Doctor")),
) -> list[dict[str, Any]]:
    """Show the full catalog to administrators and applicable prices to doctors."""
    try:
        specialty = (
            None if current_user["role"] == "Admin" else current_user["specialty"]
        )
        return await run_in_threadpool(
            ClinicService.get_clinic_services, connection, specialty
        )
    except sqlite3.Error as exc:
        raise _service_error(exc) from exc


@app.post("/api/prices")
async def add_price(
    service: ClinicServiceCreate,
    connection: sqlite3.Connection = Depends(get_db),
    _: dict[str, Any] = Depends(roles_required("Admin")),
) -> dict[str, Any]:
    """Add a priced consultation or service from the administrator's panel."""
    try:
        return await run_in_threadpool(
            ClinicService.add_clinic_service, connection, service
        )
    except sqlite3.Error as exc:
        raise _service_error(exc) from exc


@app.put("/api/prices/{service_id}")
async def update_price(
    service_id: int,
    service: ClinicServiceCreate,
    connection: sqlite3.Connection = Depends(get_db),
    _: dict[str, Any] = Depends(roles_required("Admin")),
) -> dict[str, Any]:
    """Update an existing clinic price entry."""
    try:
        return await run_in_threadpool(
            ClinicService.update_clinic_service,
            connection,
            service_id,
            service,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except sqlite3.Error as exc:
        raise _service_error(exc) from exc


@app.delete("/api/prices/{service_id}")
async def delete_price(
    service_id: int,
    connection: sqlite3.Connection = Depends(get_db),
    _: dict[str, Any] = Depends(roles_required("Admin")),
) -> dict[str, int]:
    """Remove a price entry from the clinic catalog."""
    try:
        return await run_in_threadpool(
            ClinicService.delete_clinic_service, connection, service_id
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except sqlite3.Error as exc:
        raise _service_error(exc) from exc


@app.post("/api/documents")
async def create_medical_document(
    document: MedicalDocumentCreate,
    connection: sqlite3.Connection = Depends(get_db),
    current_user: dict[str, Any] = Depends(roles_required("Admin", "Doctor")),
) -> dict[str, Any]:
    """Register a doctor's electronic prescription or referral for a partner."""
    try:
        return await run_in_threadpool(
            ClinicService.send_medical_document,
            connection,
            document,
            current_user["id"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except sqlite3.Error as exc:
        raise _service_error(exc) from exc


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000)
