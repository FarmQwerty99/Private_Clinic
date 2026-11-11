"""Authenticated clinic activity profile for a 50-user Locust run."""

import random

from locust import HttpUser, between, task


class ClinicUserSimulator(HttpUser):
    """Represent a reception employee using the clinic during a working day."""

    wait_time = between(1, 2)

    def on_start(self) -> None:
        """Sign in once so every simulated visit uses the protected work areas."""
        with self.client.post(
            "/auth/login",
            json={"login": "admin", "password": "admin123"},
            catch_response=True,
        ) as response:
            if response.status_code != 200:
                response.failure("Не удалось войти в систему клиники.")

    @task(3)
    def view_schedule(self) -> None:
        """Read the appointment journal to exercise frequent concurrent lookups."""
        self.client.get("/api/appointments")

    @task(2)
    def view_patients(self) -> None:
        """Open patient records as a reception worker would during registration."""
        self.client.get("/api/patients")

    @task(1)
    def register_random_patient(self) -> None:
        """Create a unique test patient to exercise concurrent SQLite writes."""
        suffix = random.randrange(10**9, 10**10)
        iin_suffix = random.randrange(10**11, 10**12)
        payload = {
            "full_name": f"Тестовый пациент {suffix}",
            "birth_date": "1998-03-15",
            "phone": f"+77{suffix:010d}",
            "iin": f"{iin_suffix:012d}",
        }
        self.client.post("/api/patients", json=payload)
