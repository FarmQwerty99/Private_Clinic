"""Independent, partner-scoped portal for receiving clinic medical documents."""

import hmac
import logging
import os
import secrets
import sqlite3
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database import get_db, init_db  # noqa: E402

logger = logging.getLogger(__name__)
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))
router = APIRouter()
COOKIE_NAME = "partner_portal_session"
SESSION_MAX_AGE = 8 * 60 * 60
session_serializer = URLSafeTimedSerializer(
    os.environ.get("PARTNER_SESSION_SECRET", secrets.token_urlsafe(32)),
    salt="partner-portal",
)

PARTNER_LOGINS = {
    "pharmacy": {
        "id": 1,
        "name": "Центральная Аптека №1",
        "password": os.environ.get("PHARMACY_PORTAL_PASSWORD", "pharmacy-demo"),
    },
    "hospital": {
        "id": 2,
        "name": "Городская Больница №2",
        "password": os.environ.get("HOSPITAL_PORTAL_PASSWORD", "hospital-demo"),
    },
}


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Prepare the shared clinic database before this independent portal starts."""
    await run_in_threadpool(init_db)
    yield


app = FastAPI(title="Портал медицинской организации", lifespan=lifespan)


class PartnerLogin(BaseModel):
    """Credentials for a pharmacy or hospital receiving clinic documents."""

    login: Literal["pharmacy", "hospital"]
    password: str = Field(min_length=1, max_length=256)


class DocumentStatus(BaseModel):
    """A partner confirmation that an incoming document was received or fulfilled."""

    status: Literal["Получен", "Исполнен"]


def _partner_from_request(request: Request) -> dict[str, Any] | None:
    """Resolve the portal-only signed cookie to its registered organization."""
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    try:
        session = session_serializer.loads(token, max_age=SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None
    login = session.get("partner_login")
    partner = PARTNER_LOGINS.get(login) if isinstance(login, str) else None
    return {"login": login, **partner} if partner is not None else None


async def get_active_partner(request: Request) -> dict[str, Any]:
    """Require a signed partner session and return only that partner's identity."""
    try:
        partner = _partner_from_request(request)
        if partner is None:
            raise HTTPException(
                status_code=401,
                detail="Войдите на портал вашей медицинской организации.",
            )
        return partner
    except HTTPException:
        raise
    except (AttributeError, TypeError) as exc:
        logger.exception("Не удалось проверить доступ к порталу организации.")
        raise HTTPException(
            status_code=401,
            detail="Войдите на портал вашей медицинской организации.",
        ) from exc


def _read_partner_documents(
    connection: sqlite3.Connection, partner_id: int
) -> list[dict[str, Any]]:
    """Read only the records addressed to the partner authenticated in this session."""
    try:
        documents = connection.execute(
            """
            SELECT
                m.id, m.document_type, m.details, m.status, m.created_at,
                p.full_name AS patient_name, p.med_card_num,
                e.full_name AS doctor_name, e.specialty AS doctor_specialty,
                o.name AS organization
            FROM medical_documents m
            JOIN patients p ON p.id = m.patient_id
            JOIN employees e ON e.id = m.doctor_id
            JOIN partners o ON o.id = m.partner_id
            WHERE m.partner_id = ?
            ORDER BY m.created_at DESC, m.id DESC
            """,
            (partner_id,),
        ).fetchall()
        return [dict(document) for document in documents]
    except sqlite3.Error:
        logger.exception("Не удалось загрузить входящие документы организации.")
        raise


def _update_partner_document(
    connection: sqlite3.Connection,
    document_id: int,
    partner_id: int,
    new_status: str,
) -> dict[str, Any]:
    """Apply one valid partner status transition atomically to its own record."""
    try:
        connection.execute("BEGIN IMMEDIATE")
        record = connection.execute(
            """
            SELECT status FROM medical_documents
            WHERE id = ? AND partner_id = ?
            """,
            (document_id, partner_id),
        ).fetchone()
        if record is None:
            raise LookupError("Направление в журнале этой организации не найдено.")
        expected_status = {
            "Получен": "Передан",
            "Исполнен": "Получен",
        }[new_status]
        cursor = connection.execute(
            """
            UPDATE medical_documents SET status = ?
            WHERE id = ? AND partner_id = ? AND status = ?
            """,
            (new_status, document_id, partner_id, expected_status),
        )
        if cursor.rowcount != 1:
            raise ValueError("Статус этого документа уже изменён. Обновите журнал.")
        connection.commit()
        return {"id": document_id, "status": new_status}
    except (LookupError, ValueError):
        connection.rollback()
        raise
    except sqlite3.Error:
        connection.rollback()
        logger.exception("Не удалось изменить состояние входящего документа.")
        raise


@router.get("/", response_class=HTMLResponse)
@app.get("/", response_class=HTMLResponse)
async def read_portal(
    request: Request,
    connection: sqlite3.Connection = Depends(get_db),
) -> HTMLResponse:
    """Show the partner sign-in page or that organization's incoming documents."""
    try:
        partner = _partner_from_request(request)
        documents: list[dict[str, Any]] = []
        if partner is not None:
            documents = await run_in_threadpool(
                _read_partner_documents, connection, partner["id"]
            )
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "partner": partner,
                "documents": documents,
                "base_path": (
                    "/partner"
                    if request.url.path.startswith("/partner/")
                    else ""
                ),
            },
        )
    except sqlite3.Error as exc:
        raise HTTPException(
            status_code=503,
            detail="Не удалось загрузить входящие документы. Повторите попытку позже.",
        ) from exc


def _portal_cookie_path(request: Request) -> str:
    """Scope the partner's independent session cookie to its portal path."""
    return "/partner/" if request.url.path.startswith("/partner/") else "/"


@router.post("/auth/login")
@app.post("/auth/login")
async def login(
    data: PartnerLogin,
    request: Request,
) -> JSONResponse:
    """Start an authenticated session for one configured partner organization."""
    try:
        partner = PARTNER_LOGINS[data.login]
        if not hmac.compare_digest(data.password, partner["password"]):
            raise HTTPException(
                status_code=401,
                detail="Проверьте логин и пароль медицинской организации.",
            )
        response = JSONResponse({"organization": partner["name"]})
        response.set_cookie(
            COOKIE_NAME,
            session_serializer.dumps({"partner_login": data.login}),
            max_age=SESSION_MAX_AGE,
            httponly=True,
            secure=False,
            samesite="strict",
            path=_portal_cookie_path(request),
        )
        return response
    except HTTPException:
        raise
    except (KeyError, TypeError) as exc:
        raise HTTPException(
            status_code=401,
            detail="Проверьте логин и пароль медицинской организации.",
        ) from exc


@router.post("/auth/logout")
@app.post("/auth/logout")
async def logout(request: Request) -> JSONResponse:
    """End the receiving organization's session on sign-out."""
    try:
        response = JSONResponse({"message": "Сеанс завершён."})
        response.delete_cookie(
            COOKIE_NAME,
            path=_portal_cookie_path(request),
            httponly=True,
            samesite="strict",
        )
        return response
    except (AttributeError, RuntimeError) as exc:
        logger.exception("Не удалось завершить сеанс портала организации.")
        raise HTTPException(
            status_code=400, detail="Не удалось завершить сеанс."
        ) from exc


@router.get("/api/documents")
@app.get("/api/documents")
async def get_documents(
    connection: sqlite3.Connection = Depends(get_db),
    partner: dict[str, Any] = Depends(get_active_partner),
) -> list[dict[str, Any]]:
    """Return records addressed only to the authenticated pharmacy or hospital."""
    try:
        return await run_in_threadpool(
            _read_partner_documents, connection, partner["id"]
        )
    except sqlite3.Error as exc:
        logger.exception("Ошибка чтения входящих документов организации.")
        raise HTTPException(
            status_code=503,
            detail="Не удалось загрузить входящие документы. Повторите попытку.",
        ) from exc


@router.patch("/api/documents/{document_id}")
@app.patch("/api/documents/{document_id}")
async def update_document_status(
    document_id: int,
    update: DocumentStatus,
    connection: sqlite3.Connection = Depends(get_db),
    partner: dict[str, Any] = Depends(get_active_partner),
) -> dict[str, Any]:
    """Confirm receipt or fulfillment without allowing changes to another partner's record."""
    try:
        return await run_in_threadpool(
            _update_partner_document,
            connection,
            document_id,
            partner["id"],
            update.status,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except sqlite3.Error as exc:
        logger.exception("Не удалось обновить состояние входящего документа.")
        raise HTTPException(
            status_code=503,
            detail="Не удалось изменить состояние документа. Повторите попытку.",
        ) from exc


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8001)
