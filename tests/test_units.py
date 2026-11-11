"""Focused tests for clinic initialization, security, and reception workflows."""

import sqlite3
from pathlib import Path
from typing import Generator

import pytest
from fastapi.testclient import TestClient

import database
import main
from models import AppointmentCreate, EmployeeCreate, PatientCreate
from services import ClinicService, verify_password


@pytest.fixture
def clinic_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Generator[sqlite3.Connection, None, None]:
    """Provide an isolated, freshly initialized database for each test."""
    database_path = tmp_path / "clinic.db"
    monkeypatch.setattr(database, "DB_NAME", str(database_path))
    database.init_db()
    connection = database.get_db_connection()
    yield connection
    connection.close()


@pytest.fixture
def client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Generator[TestClient, None, None]:
    """Run the web application against a temporary clinic database."""
    monkeypatch.setattr(database, "DB_NAME", str(tmp_path / "clinic.db"))
    with TestClient(main.app) as test_client:
        yield test_client


def create_doctor(connection: sqlite3.Connection, cabinet: int = 101) -> dict:
    """Register a doctor with a unique cabinet for appointment tests."""
    return ClinicService.add_employee(
        connection,
        EmployeeCreate(
            full_name="Доктор Тестов",
            specialty="Терапевт",
            employee_iin=f"{cabinet:012d}",
            cabinet=cabinet,
            role="Doctor",
            password="doctor-pass-123",
        ),
    )


def create_patient(connection: sqlite3.Connection, suffix: str = "001") -> dict:
    """Create one validated patient record for reception workflow tests."""
    return ClinicService.add_patient(
        connection,
        PatientCreate(
            full_name="Пациент Тестовый",
            birth_date="1990-01-01",
            phone=f"+7700{suffix}0000",
            iin=f"123456789{suffix}",
        ),
    )


def test_initialization_creates_only_one_hashed_administrator(
    clinic_database: sqlite3.Connection,
) -> None:
    """Confirm a clean clinic database contains exactly the requested first user."""
    employees = clinic_database.execute(
        "SELECT full_name, role, login, password_hash FROM employees"
    ).fetchall()
    assert len(employees) == 1
    assert employees[0]["full_name"] == "Главврач / Администратор клиники"
    assert employees[0]["role"] == "Admin"
    assert employees[0]["login"] == "admin"
    assert employees[0]["password_hash"] != "admin123"
    assert verify_password("admin123", employees[0]["password_hash"])
    assert clinic_database.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_employee_registration_hashes_password_and_checks_identity(
    clinic_database: sqlite3.Connection,
) -> None:
    """Verify that doctors and registrars are registered without plaintext passwords."""
    doctor = create_doctor(clinic_database)
    assert doctor["role"] == "Doctor"
    stored_hash = clinic_database.execute(
        "SELECT password_hash FROM employees WHERE id = ?", (doctor["id"],)
    ).fetchone()[0]
    assert verify_password("doctor-pass-123", stored_hash)
    assert doctor["login"].startswith("doctor-")
    assert "doktor-testov" in doctor["login"]

    same_name = ClinicService.add_employee(
        clinic_database,
        EmployeeCreate(
            full_name="Доктор Тестов",
            specialty="Кардиолог",
            employee_iin="987654321098",
            cabinet=102,
            role="Doctor",
            password="doctor-pass-456",
        ),
    )
    assert same_name["login"] == f"{doctor['login']}-2"

    with pytest.raises(ValueError, match="ИИН"):
        ClinicService.add_employee(
            clinic_database,
            EmployeeCreate(
                full_name="Доктор Тестов",
                specialty="Невролог",
                employee_iin=f"{101:012d}",
                cabinet=103,
                role="Doctor",
                password="doctor-pass-789",
            ),
        )

    with pytest.raises(ValueError, match="кабинет"):
        ClinicService.add_employee(
            clinic_database,
            EmployeeCreate(
                full_name="Другой Доктор",
                specialty="Кардиолог",
                employee_iin="987654321099",
                cabinet=101,
                role="Doctor",
                password="another-pass-123",
            ),
        )


def test_patient_card_is_generated_and_duplicates_are_reported(
    clinic_database: sqlite3.Connection,
) -> None:
    """Check IIN uniqueness and predictable clinic card-number generation."""
    patient = create_patient(clinic_database)
    assert patient["med_card_num"] == "МК-2026-0001"
    duplicate = PatientCreate(
        full_name="Другой Пациент",
        birth_date="1991-01-01",
        phone="+77009998877",
        iin=patient["iin"],
    )
    with pytest.raises(ValueError, match="ИИН"):
        ClinicService.add_patient(clinic_database, duplicate)
    assert len(ClinicService.get_all_patients(clinic_database)) == 1


def test_patient_registry_search_and_pagination(
    client: TestClient,
) -> None:
    """Keep patient history queries and rendered dashboard bounded to ten rows."""
    assert client.post(
        "/auth/login", json={"login": "admin", "password": "admin123"}
    ).status_code == 200
    for index in range(1, 24):
        response = client.post(
            "/api/patients",
            json={
                "full_name": f"Клиент {index:03d}",
                "birth_date": "1990-01-01",
                "phone": f"+7700{index:07d}",
                "iin": f"123456789{index:03d}",
            },
        )
        assert response.status_code == 200

    dashboard = client.get("/")
    assert dashboard.status_code == 200
    assert "Клиент 023" in dashboard.text
    assert "Клиент 001" not in dashboard.text

    first_page = client.get("/api/live-data?registry_page=1").json()["patient_registry"]
    third_page = client.get("/api/live-data?registry_page=3").json()["patient_registry"]
    assert first_page["total"] == 23
    assert len(first_page["items"]) == 10
    assert len(third_page["items"]) == 3
    assert third_page["page"] == 3

    searched = client.get(
        "/api/live-data?registry_search=Клиент%20017"
    ).json()["patient_registry"]
    assert searched["total"] == 1
    assert searched["items"][0]["full_name"] == "Клиент 017"

    filtered = client.get(
        "/api/live-data?registry_status=Запланирован"
    ).json()["patient_registry"]
    assert filtered["items"] == []

    patient_options = client.get("/api/patient-search").json()
    assert len(patient_options) == 10
    matching_patient = client.get(
        "/api/patient-search?search=Клиент%20017"
    ).json()
    assert len(matching_patient) == 1
    assert matching_patient[0]["full_name"] == "Клиент 017"


def test_appointment_rejects_doctor_and_room_conflicts(
    clinic_database: sqlite3.Connection,
) -> None:
    """Ensure a doctor cannot receive two bookings in the same time slot."""
    doctor = create_doctor(clinic_database)
    patient = create_patient(clinic_database)
    appointment = AppointmentCreate(
        patient_id=patient["id"],
        doctor_id=doctor["id"],
        appointment_time="2026-12-01T10:00",
    )
    saved = ClinicService.create_appointment(clinic_database, appointment)
    assert saved["cabinet"] == "101"
    patient_history = ClinicService.get_patient_registry(clinic_database)
    assert len(patient_history) == 1
    assert patient_history[0]["doctor_name"] == doctor["full_name"]
    assert patient_history[0]["appointment_status"] == "Запланирован"
    with pytest.raises(ValueError, match="время уже занято"):
        ClinicService.create_appointment(clinic_database, appointment)


def test_login_session_and_role_permissions(client: TestClient) -> None:
    """Exercise sign-in, session persistence, staff creation, and registrar access."""
    response = client.get("/api/patients")
    assert response.status_code == 401

    login_response = client.post(
        "/auth/login", json={"login": "admin", "password": "admin123"}
    )
    assert login_response.status_code == 200
    assert login_response.json()["role"] == "Admin"
    assert "password_hash" not in login_response.json()
    admin_dashboard = client.get("/")
    assert admin_dashboard.status_code == 200
    assert "Регистрация сотрудника" in admin_dashboard.text
    assert "Кабинет врача" in admin_dashboard.text

    invalid_staff = client.post(
        "/api/staff",
        json={
            "full_name": "Сотрудник Без Пароля",
            "employee_iin": "111111111111",
            "cabinet": 101,
            "role": "Doctor",
            "password": "short",
        },
    )
    assert invalid_staff.status_code == 422
    assert "специальность или отдел" in invalid_staff.json()["detail"]
    assert "пароль" in invalid_staff.json()["detail"]
    invalid_cabinet = client.post(
        "/api/staff",
        json={
            "full_name": "Регистратор Тестовый",
            "specialty": "Регистратура",
            "employee_iin": "111111111112",
            "cabinet": 101,
            "role": "Registrar",
            "password": "valid-pass-123",
        },
    )
    assert invalid_cabinet.status_code == 422
    assert "Регистратура" in invalid_cabinet.json()["detail"]

    staff_response = client.post(
        "/api/staff",
        json={
            "full_name": "Регистратор Тестовый",
            "specialty": "Регистратура",
            "employee_iin": "990099887766",
            "cabinet": "Регистратура",
            "role": "Registrar",
            "password": "register-pass-123",
        },
    )
    assert staff_response.status_code == 200
    assert staff_response.json()["cabinet"] == "Регистратура"
    assert staff_response.json()["login"].startswith("registrar-")
    duplicate_iin = client.patch(
        "/api/employees/1/iin",
        json={"employee_iin": "990099887766"},
    )
    assert duplicate_iin.status_code == 409
    identity_update = client.patch(
        "/api/employees/1/iin",
        json={"employee_iin": "990000001111"},
    )
    assert identity_update.status_code == 200
    changed_identity = client.patch(
        "/api/employees/1/iin",
        json={"employee_iin": "990000002222"},
    )
    assert changed_identity.status_code == 200
    assert changed_identity.json()["employee_iin"] == "990000002222"
    disposable_staff = client.post(
        "/api/staff",
        json={
            "full_name": "Временный Сотрудник",
            "specialty": "Регистратура",
            "employee_iin": "990099887767",
            "cabinet": "Регистратура",
            "role": "Registrar",
            "password": "temporary-pass-123",
        },
    )
    assert disposable_staff.status_code == 200
    deleted_staff = client.delete(
        f"/api/employees/{disposable_staff.json()['id']}"
    )
    assert deleted_staff.status_code == 200
    assert deleted_staff.json()["id"] == disposable_staff.json()["id"]
    remaining_staff = client.get("/api/staff").json()
    assert disposable_staff.json()["id"] not in {
        item["id"] for item in remaining_staff
    }

    client.post("/auth/logout")
    registrar_login = client.post(
        "/auth/login",
        json={
            "login": staff_response.json()["login"],
            "password": "register-pass-123",
        },
    )
    assert registrar_login.status_code == 200
    assert client.get("/api/staff").status_code == 403
    registrar_dashboard = client.get("/")
    assert "Регистратура" in registrar_dashboard.text
    assert "Кабинет врача" not in registrar_dashboard.text
    assert client.post("/api/patients", json={
        "full_name": "Пациент Из Регистратуры",
        "birth_date": "1991-04-03",
        "phone": "+77001112233",
        "iin": "990011223344",
    }).status_code == 200


def test_workspace_sessions_live_updates_and_shared_price_list(
    client: TestClient,
) -> None:
    """Keep simultaneous role logins independent and share new visits and prices."""
    admin_login = client.post(
        "/admin/auth/login", json={"login": "admin", "password": "admin123"}
    )
    assert admin_login.status_code == 200
    assert "path=/admin" in admin_login.headers["set-cookie"].lower()
    doctor = client.post(
        "/admin/api/staff",
        json={
            "full_name": "Врач Для Синхронизации",
            "specialty": "Кардиолог",
            "employee_iin": "991122334455",
            "cabinet": 303,
            "role": "Doctor",
            "password": "doctor-sync-123",
        },
    ).json()
    general_price = client.post(
        "/admin/api/prices",
        json={
            "name": "Первичная консультация",
            "specialty": "",
            "price_kzt": 8000,
            "description": "Осмотр и рекомендации",
        },
    )
    specialty_price = client.post(
        "/admin/api/prices",
        json={
            "name": "ЭКГ",
            "specialty": "Кардиолог",
            "price_kzt": 5000,
            "description": "Электрокардиограмма",
        },
    )
    assert general_price.status_code == specialty_price.status_code == 200
    registrar = client.post(
        "/admin/api/staff",
        json={
            "full_name": "Регистратор Для Синхронизации",
            "specialty": "Регистратура",
            "employee_iin": "991122334466",
            "cabinet": "Регистратура",
            "role": "Registrar",
            "password": "registrar-sync-123",
        },
    ).json()

    doctor_login = client.post(
        "/doctor/auth/login",
        json={"login": doctor["login"], "password": "doctor-sync-123"},
    )
    assert doctor_login.status_code == 200
    assert client.get("/admin/api/me").json()["role"] == "Admin"
    assert client.get("/doctor/api/me").json()["role"] == "Doctor"
    assert client.get("/api/me").status_code == 401
    admin_page = client.get("/admin/")
    doctor_page = client.get("/doctor/")
    assert 'const workspacePrefix = "/admin"' in admin_page.text
    assert 'const workspacePrefix = "/doctor"' in doctor_page.text
    assert "Прайс-лист клиники" in doctor_page.text
    assert {item["name"] for item in client.get("/doctor/api/prices").json()} == {
        "Первичная консультация",
        "ЭКГ",
    }
    assert client.post(
        "/doctor/auth/login",
        json={"login": registrar["login"], "password": "registrar-sync-123"},
    ).status_code == 403
    registrar_login = client.post(
        "/register/auth/login",
        json={"login": registrar["login"], "password": "registrar-sync-123"},
    )
    assert registrar_login.status_code == 200
    assert client.get("/register/api/me").json()["role"] == "Registrar"
    assert client.get("/admin/api/me").json()["role"] == "Admin"
    assert client.get("/doctor/api/me").json()["role"] == "Doctor"

    patient = client.post(
        "/register/api/patients",
        json={
            "full_name": "Пациент Для Обновления",
            "birth_date": "1992-05-04",
            "phone": "+77005556677",
            "iin": "992233445566",
        },
    ).json()
    appointment = client.post(
        "/register/api/appointments",
        json={
            "patient_id": patient["id"],
            "doctor_id": doctor["id"],
            "appointment_time": "2026-12-10T09:30",
        },
    )
    assert appointment.status_code == 200
    live_data = client.get("/doctor/api/live-data").json()
    assert [entry["patient_id"] for entry in live_data["appointments"]] == [
        patient["id"]
    ]
    assert [
        entry["id"] for entry in client.get("/doctor/api/patient-search").json()
    ] == [patient["id"]]
    assert client.get("/doctor/api/live-data").headers["cache-control"] == "no-store"

    changed_price = client.put(
        f"/admin/api/prices/{general_price.json()['id']}",
        json={
            "name": "Первичная консультация",
            "specialty": "",
            "price_kzt": 9000,
            "description": "Осмотр и рекомендации",
        },
    )
    assert changed_price.status_code == 200
    doctor_prices = client.get("/doctor/api/prices").json()
    assert next(item for item in doctor_prices if item["name"] == "Первичная консультация")[
        "price_kzt"
    ] == 9000
    assert client.post(
        "/doctor/api/prices",
        json={
            "name": "Нельзя добавить",
            "specialty": "",
            "price_kzt": 1000,
            "description": "",
        },
    ).status_code == 403


def test_doctor_can_only_update_active_appointments_and_portal_receives_documents(
    client: TestClient,
) -> None:
    """Require a fresh booking for care actions and verify partner-only document receipt."""
    login_response = client.post(
        "/auth/login", json={"login": "admin", "password": "admin123"}
    )
    assert login_response.status_code == 200
    employee = client.post(
        "/api/staff",
        json={
            "full_name": "Лечащий Врач",
            "specialty": "Терапевт",
            "employee_iin": "990011112222",
            "cabinet": 202,
            "role": "Doctor",
            "password": "doctor-pass-123",
        },
    ).json()
    patient = client.post(
        "/api/patients",
        json={
            "full_name": "Пациент Приёма",
            "birth_date": "1992-02-02",
            "phone": "+77002223344",
            "iin": "990022223333",
        },
    ).json()
    appointment = client.post(
        "/api/appointments",
        json={
            "patient_id": patient["id"],
            "doctor_id": employee["id"],
            "appointment_time": "2026-12-01T11:00",
        },
    ).json()
    unassigned_patient = client.post(
        "/api/patients",
        json={
            "full_name": "Пациент Другого Врача",
            "birth_date": "1993-03-03",
            "phone": "+77004445566",
            "iin": "990044445555",
        },
    ).json()

    client.post("/auth/logout")
    assert client.post(
        "/auth/login",
        json={"login": employee["login"], "password": "doctor-pass-123"},
    ).status_code == 200
    assert len(client.get("/api/appointments").json()) == 1
    visible_patients = client.get("/api/patients").json()
    assert [record["id"] for record in visible_patients] == [patient["id"]]
    assert unassigned_patient["id"] not in {
        record["id"] for record in visible_patients
    }
    document = client.post(
        "/api/documents",
        json={
            "patient_id": patient["id"],
            "partner_id": 2,
            "document_type": "Направление",
            "details": "Консультация профильного специалиста",
        },
    )
    assert document.status_code == 200
    assert "Городская Больница №2" in document.json()["message"]
    assert client.patch(
        f"/api/appointments/{appointment['id']}",
        json={"status": "Приём завершён"},
    ).status_code == 200
    assert client.get("/api/patients").json() == []
    inaccessible_document = client.post(
        "/api/documents",
        json={
            "patient_id": patient["id"],
            "partner_id": 1,
            "document_type": "Рецепт",
            "details": "Повторное назначение без новой записи",
        },
    )
    assert inaccessible_document.status_code == 404
    assert client.patch(
        f"/api/appointments/{appointment['id']}",
        json={"status": "Приём завершён"},
    ).status_code == 404
    client.post("/auth/logout")
    assert client.post(
        "/auth/login", json={"login": "admin", "password": "admin123"}
    ).status_code == 200
    rebooked = client.post(
        "/api/appointments",
        json={
            "patient_id": patient["id"],
            "doctor_id": employee["id"],
            "appointment_time": "2026-12-02T11:00",
        },
    )
    assert rebooked.status_code == 200
    client.post("/auth/logout")
    assert client.post(
        "/auth/login",
        json={"login": employee["login"], "password": "doctor-pass-123"},
    ).status_code == 200
    assert [entry["id"] for entry in client.get("/api/patients").json()] == [
        patient["id"]
    ]
    forbidden_delete = client.delete(f"/api/staff/{employee['id']}")
    assert forbidden_delete.status_code == 403
    client.post("/auth/logout")
    assert client.post(
        "/auth/login", json={"login": "admin", "password": "admin123"}
    ).status_code == 200
    protected_delete = client.delete(f"/api/staff/{employee['id']}")
    assert protected_delete.status_code == 409
    assert "сохранены его приёмы" in protected_delete.json()["detail"]
    client.post("/auth/logout")
    assert client.post(
        "/auth/login",
        json={"login": employee["login"], "password": "doctor-pass-123"},
    ).status_code == 200

    assert client.get("/partner/").status_code == 200
    assert client.get("/partner/api/documents").status_code == 401
    partner_login = client.post(
        "/partner/auth/login",
        json={"login": "hospital", "password": "hospital-demo"},
    )
    assert partner_login.status_code == 200
    assert client.get("/api/me").status_code == 200
    incoming_documents = client.get("/partner/api/documents").json()
    assert len(incoming_documents) == 1
    assert incoming_documents[0]["patient_name"] == "Пациент Приёма"
    assert client.patch(
        f"/partner/api/documents/{document.json()['id']}",
        json={"status": "Получен"},
    ).json()["status"] == "Получен"
    assert client.patch(
        f"/partner/api/documents/{document.json()['id']}",
        json={"status": "Исполнен"},
    ).json()["status"] == "Исполнен"
    client.post("/partner/auth/logout")
    assert client.post(
        "/partner/auth/login",
        json={"login": "pharmacy", "password": "pharmacy-demo"},
    ).status_code == 200
    assert client.get("/partner/api/documents").json() == []
    doctor_dashboard = client.get("/")
    assert "Кабинет врача" in doctor_dashboard.text
    assert 'data-tab="registry"' not in doctor_dashboard.text
    assert "Исполнен" in doctor_dashboard.text
    assert client.post(
        "/api/patients",
        json={
            "full_name": "Новая Карта",
            "birth_date": "1994-01-01",
            "phone": "+77003334455",
            "iin": "990033334444",
        },
    ).status_code == 403
