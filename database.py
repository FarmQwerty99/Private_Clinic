"""SQLite schema and connection lifecycle for the private clinic application."""

import logging
import os
import sqlite3
from pathlib import Path
from typing import Generator

DB_NAME = str(
    Path(
        os.environ.get(
            "CLINIC_DB_PATH",
            str(Path(__file__).resolve().with_name("clinic.db")),
        )
    ).resolve()
)
logger = logging.getLogger(__name__)


def get_db_connection() -> sqlite3.Connection:
    """Open a thread-safe SQLite connection with clinic-safe concurrency settings."""
    try:
        connection = sqlite3.connect(
            DB_NAME,
            timeout=30,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON;")
        connection.execute("PRAGMA busy_timeout = 30000;")
        return connection
    except sqlite3.Error:
        logger.exception("Не удалось открыть базу данных клиники.")
        raise


def init_db() -> None:
    """Create the clinic schema and seed only the initial administrator account."""
    connection = get_db_connection()
    try:
        connection.execute("PRAGMA journal_mode = WAL;")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS employees (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                specialty TEXT NOT NULL,
                employee_iin TEXT,
                cabinet TEXT,
                role TEXT NOT NULL CHECK (role IN ('Admin', 'Doctor', 'Registrar')),
                login TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_employees_doctor_cabinet
                ON employees(cabinet)
                WHERE role = 'Doctor' AND cabinet IS NOT NULL;

            CREATE TABLE IF NOT EXISTS patients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                birth_date TEXT NOT NULL,
                phone TEXT NOT NULL UNIQUE,
                iin TEXT NOT NULL UNIQUE,
                med_card_num TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_patients_full_name
                ON patients(full_name);

            CREATE TABLE IF NOT EXISTS appointments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id INTEGER NOT NULL REFERENCES patients(id),
                doctor_id INTEGER NOT NULL REFERENCES employees(id),
                cabinet INTEGER NOT NULL,
                appointment_time TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Запланирован',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_appointments_doctor_time
                ON appointments(doctor_id, appointment_time)
                WHERE status != 'Отменён';

            CREATE UNIQUE INDEX IF NOT EXISTS idx_appointments_cabinet_time
                ON appointments(cabinet, appointment_time)
                WHERE status != 'Отменён';

            CREATE INDEX IF NOT EXISTS idx_appointments_time
                ON appointments(appointment_time);

            CREATE TABLE IF NOT EXISTS partners (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                partner_type TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS medical_documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id INTEGER NOT NULL REFERENCES patients(id),
                doctor_id INTEGER NOT NULL REFERENCES employees(id),
                partner_id INTEGER NOT NULL REFERENCES partners(id),
                document_type TEXT NOT NULL
                    CHECK (document_type IN ('Рецепт', 'Направление')),
                details TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Передан',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS clinic_services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                specialty TEXT NOT NULL DEFAULT '',
                price_kzt INTEGER NOT NULL CHECK (price_kzt > 0),
                description TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_clinic_services_specialty
                ON clinic_services(specialty);
            """
        )

        employee_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(employees)").fetchall()
        }
        if "employee_iin" not in employee_columns:
            connection.execute("ALTER TABLE employees ADD COLUMN employee_iin TEXT")
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_employees_employee_iin
                ON employees(employee_iin)
                WHERE employee_iin IS NOT NULL
            """
        )

        # Importing here keeps database initialization independent of module load order.
        from services import hash_password

        employee_count = connection.execute(
            "SELECT COUNT(*) FROM employees"
        ).fetchone()[0]
        if employee_count == 0:
            connection.execute(
                """
                INSERT INTO employees
                    (full_name, specialty, cabinet, role, login, password_hash)
                VALUES (?, ?, NULL, 'Admin', ?, ?)
                """,
                (
                    "Главврач / Администратор клиники",
                    "Администрация",
                    "admin",
                    hash_password("admin123"),
                ),
            )

        connection.executemany(
            """
            INSERT OR IGNORE INTO partners (id, name, partner_type)
            VALUES (?, ?, ?)
            """,
            [
                (1, "Центральная Аптека №1", "Аптека"),
                (2, "Городская Больница №2", "Больница"),
            ],
        )
        connection.commit()
    except sqlite3.Error:
        connection.rollback()
        logger.exception("Не удалось подготовить базу данных клиники.")
        raise
    finally:
        connection.close()


def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Provide one request-scoped connection and always close it after the request."""
    connection = get_db_connection()
    try:
        yield connection
    finally:
        connection.close()
