"""Clinic business operations, including authentication and medical workflows."""

import hashlib
import hmac
import logging
import re
import secrets
import sqlite3
from typing import Any

from models import (
    AppointmentCreate,
    ClinicServiceCreate,
    EmployeeCreate,
    EmployeeIdentityUpdate,
    MedicalDocumentCreate,
    PatientCreate,
)

logger = logging.getLogger(__name__)
PASSWORD_ITERATIONS = 200_000
CYRILLIC_TRANSLATION = str.maketrans(
    {
        "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e",
        "ё": "yo", "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k",
        "л": "l", "м": "m", "н": "n", "о": "o", "п": "p", "р": "r",
        "с": "s", "т": "t", "у": "u", "ф": "f", "х": "h", "ц": "ts",
        "ч": "ch", "ш": "sh", "щ": "sch", "ъ": "", "ы": "y", "ь": "",
        "э": "e", "ю": "yu", "я": "ya",
        "ә": "a", "ғ": "g", "қ": "q", "ң": "n", "ө": "o", "ұ": "u",
        "ү": "u", "һ": "h", "і": "i",
    }
)


def _employee_login(
    connection: sqlite3.Connection, full_name: str, role: str
) -> str:
    """Create a unique, readable login containing the staff role and name."""
    prefix = "doctor" if role == "Doctor" else "registrar"
    transliterated = full_name.strip().lower().translate(CYRILLIC_TRANSLATION)
    name_part = "-".join(re.findall(r"[a-z0-9]+", transliterated))[:48].strip("-")
    base = f"{prefix}-{name_part or 'staff'}"
    candidate = base
    suffix = 2
    while connection.execute(
        "SELECT 1 FROM employees WHERE login = ?", (candidate,)
    ).fetchone():
        candidate = f"{base}-{suffix}"
        suffix += 1
    return candidate


def hash_password(password: str) -> str:
    """Hash a staff password with a unique salt before it is stored in SQLite."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a submitted password without exposing the stored credential hash."""
    try:
        algorithm, iteration_text, salt_hex, digest_hex = stored_hash.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        iterations = int(iteration_text)
        if iterations < 1:
            return False
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), iterations
        )
        return hmac.compare_digest(actual, expected)
    except (AttributeError, TypeError, ValueError):
        return False


class ClinicService:
    """Implement clinic workflows using the request-scoped SQLite connection."""

    @staticmethod
    def authenticate(
        connection: sqlite3.Connection, login: str, password: str
    ) -> dict[str, Any]:
        """Find a staff account and verify its salted password hash for sign-in."""
        try:
            employee = connection.execute(
                """
                SELECT id, full_name, role, specialty, cabinet, login, password_hash
                FROM employees
                WHERE login = ?
                """,
                (login.strip(),),
            ).fetchone()
            if employee is None or not verify_password(
                password, employee["password_hash"]
            ):
                raise ValueError("Проверьте логин и пароль сотрудника.")
            return ClinicService._public_employee(employee)
        except sqlite3.Error:
            logger.exception("Не удалось проверить учётную запись сотрудника.")
            raise

    @staticmethod
    def get_employee(
        connection: sqlite3.Connection, employee_id: int
    ) -> dict[str, Any] | None:
        """Load a session employee without returning any authentication material."""
        try:
            employee = connection.execute(
                """
                SELECT id, full_name, role, specialty, cabinet, login
                FROM employees
                WHERE id = ?
                """,
                (employee_id,),
            ).fetchone()
            return dict(employee) if employee else None
        except sqlite3.Error:
            logger.exception("Не удалось загрузить данные сотрудника.")
            raise

    @staticmethod
    def add_employee(
        connection: sqlite3.Connection, employee: EmployeeCreate
    ) -> dict[str, Any]:
        """Register a doctor or registrar from the administrator's staff screen."""
        try:
            generated_login = _employee_login(
                connection, employee.full_name, employee.role
            )
            cursor = connection.execute(
                """
                INSERT INTO employees
                    (full_name, specialty, employee_iin, cabinet, role, login, password_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    employee.full_name.strip(),
                    employee.specialty.strip(),
                    employee.employee_iin,
                    employee.cabinet,
                    employee.role,
                    generated_login,
                    hash_password(employee.password),
                ),
            )
            connection.commit()
            result = ClinicService.get_employee(connection, cursor.lastrowid)
            if result is None:
                raise RuntimeError("Созданный сотрудник не найден.")
            return result
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            error = str(exc)
            if "idx_employees_employee_iin" in error or "employees.employee_iin" in error:
                raise ValueError("Сотрудник с таким ИИН уже зарегистрирован.") from exc
            if "idx_employees_doctor_cabinet" in error or "employees.cabinet" in error:
                raise ValueError("Этот кабинет уже закреплён за другим врачом.") from exc
            if "employees.login" in error:
                raise ValueError("Логин сотрудника уже используется.") from exc
            raise ValueError("Проверьте логин и кабинет сотрудника.") from exc
        except sqlite3.Error:
            connection.rollback()
            logger.exception("Не удалось зарегистрировать сотрудника.")
            raise

    @staticmethod
    def get_all_employees(connection: sqlite3.Connection) -> list[dict[str, Any]]:
        """Return the clinic roster without password hashes for the admin panel."""
        try:
            employees = connection.execute(
                """
                SELECT id, full_name, specialty, employee_iin, cabinet, role, login
                FROM employees
                ORDER BY role, full_name
                """
            ).fetchall()
            return [dict(employee) for employee in employees]
        except sqlite3.Error:
            logger.exception("Не удалось получить список сотрудников.")
            raise

    @staticmethod
    def update_employee_iin(
        connection: sqlite3.Connection,
        employee_id: int,
        identity: EmployeeIdentityUpdate,
    ) -> dict[str, Any]:
        """Set or change an employee's unique IIN, including older staff records."""
        try:
            employee = connection.execute(
                "SELECT id, employee_iin FROM employees WHERE id = ?", (employee_id,)
            ).fetchone()
            if employee is None:
                raise ValueError("Сотрудник не найден в штате клиники.")
            cursor = connection.execute(
                """
                UPDATE employees SET employee_iin = ?
                WHERE id = ?
                """,
                (identity.employee_iin, employee_id),
            )
            if cursor.rowcount == 0:
                connection.rollback()
                return {"id": employee_id, "employee_iin": identity.employee_iin}
            connection.commit()
            return {"id": employee_id, "employee_iin": identity.employee_iin}
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            error = str(exc)
            if "idx_employees_employee_iin" in error or "employees.employee_iin" in error:
                raise ValueError("Сотрудник с таким ИИН уже зарегистрирован.") from exc
            raise ValueError("Не удалось обновить ИИН сотрудника.") from exc
        except ValueError:
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            logger.exception("Не удалось обновить ИИН сотрудника.")
            raise

    @staticmethod
    def delete_employee(
        connection: sqlite3.Connection,
        employee_id: int,
        current_employee_id: int,
    ) -> dict[str, int]:
        """Remove an unused staff account without breaking medical history."""
        try:
            connection.execute("BEGIN IMMEDIATE")
            employee = connection.execute(
                "SELECT id, role FROM employees WHERE id = ?", (employee_id,)
            ).fetchone()
            if employee is None:
                raise ValueError("Сотрудник не найден в штате клиники.")
            if employee_id == current_employee_id:
                raise ValueError("Нельзя удалить собственную учётную запись.")
            if employee["role"] == "Admin":
                raise ValueError("Учётную запись администратора нельзя удалить.")

            appointment_count = connection.execute(
                "SELECT COUNT(*) FROM appointments WHERE doctor_id = ?",
                (employee_id,),
            ).fetchone()[0]
            document_count = connection.execute(
                "SELECT COUNT(*) FROM medical_documents WHERE doctor_id = ?",
                (employee_id,),
            ).fetchone()[0]
            if appointment_count or document_count:
                raise ValueError(
                    "Сотрудника нельзя удалить: в системе сохранены его приёмы "
                    "или медицинские документы."
                )

            connection.execute("DELETE FROM employees WHERE id = ?", (employee_id,))
            connection.commit()
            return {"id": employee_id}
        except ValueError:
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            logger.exception("Не удалось удалить сотрудника.")
            raise

    @staticmethod
    def get_doctors(connection: sqlite3.Connection) -> list[dict[str, Any]]:
        """List practicing doctors for reception scheduling and clinical records."""
        try:
            doctors = connection.execute(
                """
                SELECT id, full_name, specialty, cabinet
                FROM employees
                WHERE role = 'Doctor'
                ORDER BY full_name
                """
            ).fetchall()
            return [dict(doctor) for doctor in doctors]
        except sqlite3.Error:
            logger.exception("Не удалось получить список врачей.")
            raise

    @staticmethod
    def add_patient(
        connection: sqlite3.Connection, patient: PatientCreate
    ) -> dict[str, Any]:
        """Create a patient record and issue its unique clinic medical-card number."""
        try:
            connection.execute("BEGIN IMMEDIATE")
            next_id = connection.execute(
                "SELECT COALESCE(MAX(id), 0) + 1 FROM patients"
            ).fetchone()[0]
            card_number = f"МК-2026-{next_id:04d}"
            connection.execute(
                """
                INSERT INTO patients
                    (id, full_name, birth_date, phone, iin, med_card_num)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    next_id,
                    patient.full_name.strip(),
                    patient.birth_date,
                    patient.phone,
                    patient.iin,
                    card_number,
                ),
            )
            connection.commit()
            return {
                "id": next_id,
                "full_name": patient.full_name.strip(),
                "birth_date": patient.birth_date,
                "phone": patient.phone,
                "iin": patient.iin,
                "med_card_num": card_number,
            }
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            if "patients.iin" in str(exc):
                raise ValueError("Пациент с таким ИИН уже зарегистрирован.") from exc
            if "patients.phone" in str(exc):
                raise ValueError("Этот номер телефона уже указан в карте пациента.") from exc
            raise ValueError("Не удалось оформить карту пациента с указанными данными.") from exc
        except sqlite3.Error:
            connection.rollback()
            logger.exception("Не удалось оформить пациента.")
            raise

    @staticmethod
    def get_all_patients(
        connection: sqlite3.Connection, doctor_id: int | None = None
    ) -> list[dict[str, Any]]:
        """List clinic patients, limiting a physician to their assigned consultations."""
        try:
            query = """
                SELECT id, full_name, birth_date, phone, iin, med_card_num
                FROM patients
            """
            parameters: tuple[int, ...] = ()
            if doctor_id is not None:
                query = """
                    SELECT DISTINCT p.id, p.full_name, p.birth_date, p.phone,
                        p.iin, p.med_card_num
                    FROM patients p
                    JOIN appointments a ON a.patient_id = p.id
                    WHERE a.doctor_id = ? AND a.status = 'Запланирован'
                """
                parameters = (doctor_id,)
                query += " ORDER BY p.id DESC"
            else:
                query += " ORDER BY id DESC"
            patients = connection.execute(query, parameters).fetchall()
            return [dict(patient) for patient in patients]
        except sqlite3.Error:
            logger.exception("Не удалось получить список пациентов.")
            raise

    @staticmethod
    def get_patient_registry(
        connection: sqlite3.Connection,
    ) -> list[dict[str, Any]]:
        """Show each registered patient with every associated doctor and visit status."""
        try:
            rows = connection.execute(
                """
                SELECT
                    p.id AS patient_id, p.full_name, p.iin, p.birth_date,
                    p.phone, p.med_card_num, p.created_at AS registered_at,
                    a.appointment_time, a.status AS appointment_status,
                    e.full_name AS doctor_name, e.specialty AS doctor_specialty,
                    a.cabinet
                FROM patients p
                LEFT JOIN appointments a ON a.patient_id = p.id
                LEFT JOIN employees e ON e.id = a.doctor_id
                ORDER BY p.created_at DESC, p.id DESC, a.appointment_time DESC
                """
            ).fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error:
            logger.exception("Не удалось загрузить историю пациентов регистратуры.")
            raise

    @staticmethod
    def get_patient_registry_page(
        connection: sqlite3.Connection,
        page: int = 1,
        page_size: int = 10,
        search: str = "",
        status: str = "",
    ) -> dict[str, Any]:
        """Return one bounded patient-history page and its filtered result count."""
        try:
            filters: list[str] = []
            parameters: list[Any] = []
            normalized_search = search.strip()
            if normalized_search:
                escaped_search = (
                    normalized_search.replace("\\", "\\\\")
                    .replace("%", "\\%")
                    .replace("_", "\\_")
                )
                pattern = f"%{escaped_search}%"
                filters.append(
                    """
                    (p.full_name LIKE ? ESCAPE '\\'
                     OR p.iin LIKE ? ESCAPE '\\'
                     OR p.phone LIKE ? ESCAPE '\\'
                     OR p.med_card_num LIKE ? ESCAPE '\\'
                     OR COALESCE(e.full_name, '') LIKE ? ESCAPE '\\')
                    """
                )
                parameters.extend([pattern] * 5)
            if status == "Ожидает записи":
                filters.append("a.id IS NULL")
            elif status:
                filters.append("a.status = ?")
                parameters.append(status)

            where_clause = f" WHERE {' AND '.join(filters)}" if filters else ""
            total = connection.execute(
                f"""
                SELECT COUNT(*)
                FROM patients p
                LEFT JOIN appointments a ON a.patient_id = p.id
                LEFT JOIN employees e ON e.id = a.doctor_id
                {where_clause}
                """,
                parameters,
            ).fetchone()[0]
            rows = connection.execute(
                f"""
                SELECT
                    p.id AS patient_id, p.full_name, p.iin, p.birth_date,
                    p.phone, p.med_card_num, p.created_at AS registered_at,
                    a.appointment_time, a.status AS appointment_status,
                    e.full_name AS doctor_name, e.specialty AS doctor_specialty,
                    a.cabinet
                FROM patients p
                LEFT JOIN appointments a ON a.patient_id = p.id
                LEFT JOIN employees e ON e.id = a.doctor_id
                {where_clause}
                ORDER BY p.created_at DESC, p.id DESC, a.appointment_time DESC
                LIMIT ? OFFSET ?
                """,
                [*parameters, page_size, (page - 1) * page_size],
            ).fetchall()
            return {
                "items": [dict(row) for row in rows],
                "total": total,
                "page": page,
                "page_size": page_size,
            }
        except sqlite3.Error:
            logger.exception("Не удалось загрузить страницу картотеки пациентов.")
            raise

    @staticmethod
    def search_patients(
        connection: sqlite3.Connection,
        search: str = "",
        doctor_id: int | None = None,
        limit: int = 10,
    ) -> list[dict[str, Any]]:
        """Find a small patient-choice list instead of loading all patient cards."""
        try:
            filters: list[str] = []
            parameters: list[Any] = []
            if doctor_id is not None:
                filters.append(
                    "EXISTS (SELECT 1 FROM appointments a "
                    "WHERE a.patient_id = p.id AND a.doctor_id = ? "
                    "AND a.status = 'Запланирован')"
                )
                parameters.append(doctor_id)
            normalized_search = search.strip()
            if normalized_search:
                escaped_search = (
                    normalized_search.replace("\\", "\\\\")
                    .replace("%", "\\%")
                    .replace("_", "\\_")
                )
                pattern = f"%{escaped_search}%"
                filters.append(
                    "(p.full_name LIKE ? ESCAPE '\\' "
                    "OR p.iin LIKE ? ESCAPE '\\' "
                    "OR p.phone LIKE ? ESCAPE '\\' "
                    "OR p.med_card_num LIKE ? ESCAPE '\\')"
                )
                parameters.extend([pattern] * 4)
            where_clause = f" WHERE {' AND '.join(filters)}" if filters else ""
            rows = connection.execute(
                f"""
                SELECT p.id, p.full_name, p.med_card_num
                FROM patients p
                {where_clause}
                ORDER BY p.id DESC
                LIMIT ?
                """,
                [*parameters, limit],
            ).fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error:
            logger.exception("Не удалось выполнить поиск карт пациентов.")
            raise

    @staticmethod
    def create_appointment(
        connection: sqlite3.Connection, appointment: AppointmentCreate
    ) -> dict[str, Any]:
        """Book a doctor and cabinet time slot atomically to prevent double booking."""
        try:
            connection.execute("BEGIN IMMEDIATE")
            doctor = connection.execute(
                """
                SELECT cabinet
                FROM employees
                WHERE id = ? AND role = 'Doctor'
                """,
                (appointment.doctor_id,),
            ).fetchone()
            if doctor is None:
                raise ValueError("Выбранный врач не найден в расписании клиники.")
            patient = connection.execute(
                "SELECT id FROM patients WHERE id = ?", (appointment.patient_id,)
            ).fetchone()
            if patient is None:
                raise ValueError("Пациент не найден в картотеке клиники.")

            cursor = connection.execute(
                """
                INSERT INTO appointments
                    (patient_id, doctor_id, cabinet, appointment_time)
                VALUES (?, ?, ?, ?)
                """,
                (
                    appointment.patient_id,
                    appointment.doctor_id,
                    doctor["cabinet"],
                    appointment.appointment_time,
                ),
            )
            connection.commit()
            return {
                "id": cursor.lastrowid,
                "patient_id": appointment.patient_id,
                "doctor_id": appointment.doctor_id,
                "cabinet": doctor["cabinet"],
                "appointment_time": appointment.appointment_time,
                "status": "Запланирован",
            }
        except ValueError:
            connection.rollback()
            raise
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise ValueError(
                "Это время уже занято врачом или кабинетом. Выберите другой интервал."
            ) from exc
        except sqlite3.Error:
            connection.rollback()
            logger.exception("Не удалось записать пациента на приём.")
            raise

    @staticmethod
    def get_schedule(
        connection: sqlite3.Connection, doctor_id: int | None = None
    ) -> list[dict[str, Any]]:
        """Return the appointment journal, optionally limited to one doctor's visits."""
        try:
            query = """
                SELECT
                    a.id, a.patient_id, a.doctor_id, a.cabinet,
                    p.full_name AS patient_name, p.med_card_num, p.phone,
                    d.full_name AS doctor_name, d.specialty AS doctor_specialty,
                    a.appointment_time, a.status
                FROM appointments a
                JOIN patients p ON p.id = a.patient_id
                JOIN employees d ON d.id = a.doctor_id
            """
            parameters: tuple[int, ...] = ()
            if doctor_id is not None:
                query += " WHERE a.doctor_id = ?"
                parameters = (doctor_id,)
            query += " ORDER BY a.appointment_time"
            appointments = connection.execute(query, parameters).fetchall()
            return [dict(appointment) for appointment in appointments]
        except sqlite3.Error:
            logger.exception("Не удалось загрузить журнал приёмов.")
            raise

    @staticmethod
    def get_medical_documents(
        connection: sqlite3.Connection, doctor_id: int | None = None
    ) -> list[dict[str, Any]]:
        """List electronic documents and their receipt status at partner facilities."""
        try:
            query = """
                SELECT
                    m.id, m.document_type, m.details, m.status, m.created_at,
                    p.full_name AS patient_name, p.med_card_num,
                    e.full_name AS doctor_name, o.name AS organization
                FROM medical_documents m
                JOIN patients p ON p.id = m.patient_id
                JOIN employees e ON e.id = m.doctor_id
                JOIN partners o ON o.id = m.partner_id
            """
            parameters: tuple[int, ...] = ()
            if doctor_id is not None:
                query += " WHERE m.doctor_id = ?"
                parameters = (doctor_id,)
            query += " ORDER BY m.created_at DESC, m.id DESC"
            documents = connection.execute(query, parameters).fetchall()
            return [dict(document) for document in documents]
        except sqlite3.Error:
            logger.exception("Не удалось загрузить электронные рецепты и направления.")
            raise

    @staticmethod
    def update_appointment_status(
        connection: sqlite3.Connection,
        appointment_id: int,
        status: str,
        doctor_id: int | None = None,
    ) -> dict[str, Any]:
        """Record an outcome once for an active appointment assigned to this doctor."""
        try:
            query = """
                UPDATE appointments SET status = ?
                WHERE id = ? AND status = 'Запланирован'
            """
            parameters: tuple[Any, ...] = (status, appointment_id)
            if doctor_id is not None:
                query += " AND doctor_id = ?"
                parameters += (doctor_id,)
            cursor = connection.execute(query, parameters)
            if cursor.rowcount == 0:
                connection.rollback()
                raise ValueError(
                    "Приём уже завершён, отменён или не относится к этому врачу."
                )
            connection.commit()
            return {"id": appointment_id, "status": status}
        except ValueError:
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            logger.exception("Не удалось обновить статус приёма.")
            raise

    @staticmethod
    def get_partners(connection: sqlite3.Connection) -> list[dict[str, Any]]:
        """List approved city pharmacies and hospitals available for documents."""
        try:
            partners = connection.execute(
                "SELECT id, name, partner_type FROM partners ORDER BY id"
            ).fetchall()
            return [dict(partner) for partner in partners]
        except sqlite3.Error:
            logger.exception("Не удалось получить список медицинских организаций.")
            raise

    @staticmethod
    def get_clinic_services(
        connection: sqlite3.Connection, specialty: str | None = None
    ) -> list[dict[str, Any]]:
        """Return all prices for administrators or relevant prices for one doctor."""
        try:
            query = """
                SELECT id, name, specialty, price_kzt, description
                FROM clinic_services
            """
            parameters: tuple[str, ...] = ()
            if specialty is not None:
                query += " WHERE specialty = '' OR specialty = ?"
                parameters = (specialty,)
            query += " ORDER BY specialty, name"
            rows = connection.execute(query, parameters).fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error:
            logger.exception("Не удалось загрузить прайс-лист клиники.")
            raise

    @staticmethod
    def add_clinic_service(
        connection: sqlite3.Connection, service: ClinicServiceCreate
    ) -> dict[str, Any]:
        """Add a priced medical service to the clinic-wide catalog."""
        try:
            cursor = connection.execute(
                """
                INSERT INTO clinic_services (name, specialty, price_kzt, description)
                VALUES (?, ?, ?, ?)
                """,
                (service.name, service.specialty, service.price_kzt, service.description),
            )
            connection.commit()
            return {
                "id": cursor.lastrowid,
                "name": service.name,
                "specialty": service.specialty,
                "price_kzt": service.price_kzt,
                "description": service.description,
            }
        except sqlite3.Error:
            connection.rollback()
            logger.exception("Не удалось добавить услугу в прайс-лист.")
            raise

    @staticmethod
    def update_clinic_service(
        connection: sqlite3.Connection,
        service_id: int,
        service: ClinicServiceCreate,
    ) -> dict[str, Any]:
        """Update a price-list entry without changing its identity."""
        try:
            cursor = connection.execute(
                """
                UPDATE clinic_services
                SET name = ?, specialty = ?, price_kzt = ?, description = ?
                WHERE id = ?
                """,
                (
                    service.name,
                    service.specialty,
                    service.price_kzt,
                    service.description,
                    service_id,
                ),
            )
            if cursor.rowcount == 0:
                raise ValueError("Услуга не найдена в прайс-листе клиники.")
            connection.commit()
            return {"id": service_id, **service.model_dump()}
        except ValueError:
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            logger.exception("Не удалось изменить цену медицинской услуги.")
            raise

    @staticmethod
    def delete_clinic_service(
        connection: sqlite3.Connection, service_id: int
    ) -> dict[str, int]:
        """Remove a service from the clinic price list."""
        try:
            cursor = connection.execute(
                "DELETE FROM clinic_services WHERE id = ?", (service_id,)
            )
            if cursor.rowcount == 0:
                raise ValueError("Услуга не найдена в прайс-листе клиники.")
            connection.commit()
            return {"id": service_id}
        except ValueError:
            connection.rollback()
            raise
        except sqlite3.Error:
            connection.rollback()
            logger.exception("Не удалось удалить услугу из прайс-листа.")
            raise

    @staticmethod
    def send_medical_document(
        connection: sqlite3.Connection,
        document: MedicalDocumentCreate,
        doctor_id: int,
    ) -> dict[str, Any]:
        """Register an electronic prescription or referral for its selected partner."""
        try:
            patient = connection.execute(
                "SELECT id FROM patients WHERE id = ?", (document.patient_id,)
            ).fetchone()
            if patient is None:
                raise ValueError("Пациент не найден в картотеке клиники.")
            employee = connection.execute(
                "SELECT role FROM employees WHERE id = ?", (doctor_id,)
            ).fetchone()
            if employee is not None and employee["role"] == "Doctor":
                appointment = connection.execute(
                    """
                    SELECT id FROM appointments
                    WHERE patient_id = ? AND doctor_id = ? AND status = 'Запланирован'
                    LIMIT 1
                    """,
                    (document.patient_id, doctor_id),
                ).fetchone()
                if appointment is None:
                    raise ValueError(
                        "Для оформления документа пациент должен быть записан к этому врачу."
                    )
            partner = connection.execute(
                "SELECT name, partner_type FROM partners WHERE id = ?",
                (document.partner_id,),
            ).fetchone()
            if partner is None:
                raise ValueError("Выбранная медицинская организация не найдена.")
            cursor = connection.execute(
                """
                INSERT INTO medical_documents
                    (patient_id, doctor_id, partner_id, document_type, details)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    document.patient_id,
                    doctor_id,
                    document.partner_id,
                    document.document_type,
                    document.details.strip(),
                ),
            )
            connection.commit()
            return {
                "id": cursor.lastrowid,
                "status": "Передан",
                "organization": partner["name"],
                "type": document.document_type,
                "message": (
                    f"{document.document_type} успешно отправлен в {partner['name']}."
                ),
            }
        except sqlite3.Error:
            connection.rollback()
            logger.exception("Не удалось зарегистрировать медицинский документ.")
            raise

    @staticmethod
    def _public_employee(employee: sqlite3.Row) -> dict[str, Any]:
        """Shape a staff record for session use while omitting its password hash."""
        return {
            "id": employee["id"],
            "full_name": employee["full_name"],
            "role": employee["role"],
            "specialty": employee["specialty"],
            "cabinet": employee["cabinet"],
            "login": employee["login"],
        }
