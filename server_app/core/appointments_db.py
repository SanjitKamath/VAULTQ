import sqlite3
import threading
import time
import secrets
from pathlib import Path
from typing import Optional, List, Dict

from .audit_logger import get_audit_logger

APPOINTMENT_VALID_HOURS = 24


def _now_ts() -> int:
    return int(time.time())


class AppointmentDB:
    def __init__(self):
        self.audit = get_audit_logger()
        base_dir = Path(__file__).resolve().parents[1]
        self.db_file = base_dir / "storage" / "appointments.db"
        self._lock = threading.Lock()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        self.db_file.parent.mkdir(parents=True, exist_ok=True)
        with self._get_conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS appointments (
                    apt_id TEXT PRIMARY KEY,
                    doctor_id TEXT NOT NULL,
                    patient_id TEXT NOT NULL,
                    appointment_time INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    created_at INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_appointments_doc ON appointments (doctor_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_appointments_pat ON appointments (patient_id)"
            )
        self.audit.info("Appointments DB initialized at %s", self.db_file)

    def add_appointment(
        self,
        doctor_id: str,
        patient_id: str,
        appointment_time: int,
        expires_at: Optional[int] = None,
    ) -> Dict:
        doctor_id = (doctor_id or "").strip()
        patient_id = (patient_id or "").strip()
        if not doctor_id or not patient_id:
            raise ValueError("doctor_id and patient_id are required")
        if appointment_time <= 0:
            raise ValueError("appointment_time must be a valid epoch timestamp")
        if expires_at is None:
            expires_at = int(appointment_time + (APPOINTMENT_VALID_HOURS * 3600))
        if expires_at < appointment_time:
            raise ValueError("expires_at must be >= appointment_time")

        apt_id = f"apt_{secrets.token_hex(4)}"
        now_ts = _now_ts()
        with self._lock, self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO appointments (apt_id, doctor_id, patient_id, appointment_time, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (apt_id, doctor_id, patient_id, int(appointment_time), int(expires_at), now_ts),
            )
        self.audit.info(
            "Appointment created: apt_id=%s doctor_id=%s patient_id=%s appointment_time=%s expires_at=%s",
            apt_id,
            doctor_id,
            patient_id,
            int(appointment_time),
            int(expires_at),
        )
        return {
            "apt_id": apt_id,
            "doctor_id": doctor_id,
            "patient_id": patient_id,
            "appointment_time": int(appointment_time),
            "expires_at": int(expires_at),
            "created_at": now_ts,
        }

    def delete_appointment(self, apt_id: str) -> bool:
        apt_id = (apt_id or "").strip()
        if not apt_id:
            return False
        with self._lock, self._get_conn() as conn:
            cur = conn.execute("DELETE FROM appointments WHERE apt_id = ?", (apt_id,))
            deleted = cur.rowcount > 0
        if deleted:
            self.audit.info("Appointment deleted: apt_id=%s", apt_id)
        return deleted

    def update_appointment(
        self,
        apt_id: str,
        doctor_id: str,
        patient_id: str,
        appointment_time: int,
        expires_at: Optional[int] = None,
    ) -> Optional[Dict]:
        apt_id = (apt_id or "").strip()
        doctor_id = (doctor_id or "").strip()
        patient_id = (patient_id or "").strip()
        if not apt_id:
            raise ValueError("apt_id is required")
        if not doctor_id or not patient_id:
            raise ValueError("doctor_id and patient_id are required")
        if appointment_time <= 0:
            raise ValueError("appointment_time must be a valid epoch timestamp")
        if expires_at is None:
            expires_at = int(appointment_time + (APPOINTMENT_VALID_HOURS * 3600))
        if expires_at < appointment_time:
            raise ValueError("expires_at must be >= appointment_time")

        with self._lock, self._get_conn() as conn:
            cur = conn.execute(
                """
                UPDATE appointments
                SET doctor_id = ?, patient_id = ?, appointment_time = ?, expires_at = ?
                WHERE apt_id = ?
                """,
                (doctor_id, patient_id, int(appointment_time), int(expires_at), apt_id),
            )
            if cur.rowcount == 0:
                return None

        self.audit.info(
            "Appointment updated: apt_id=%s doctor_id=%s patient_id=%s appointment_time=%s expires_at=%s",
            apt_id,
            doctor_id,
            patient_id,
            int(appointment_time),
            int(expires_at),
        )
        return {
            "apt_id": apt_id,
            "doctor_id": doctor_id,
            "patient_id": patient_id,
            "appointment_time": int(appointment_time),
            "expires_at": int(expires_at),
        }

    def list_appointments(
        self,
        doctor_id: Optional[str] = None,
        patient_id: Optional[str] = None,
    ) -> List[Dict]:
        filters = []
        params = []
        if doctor_id:
            filters.append("doctor_id = ?")
            params.append(doctor_id)
        if patient_id:
            filters.append("patient_id = ?")
            params.append(patient_id)
        where_clause = f"WHERE {' AND '.join(filters)}" if filters else ""
        query = (
            "SELECT apt_id, doctor_id, patient_id, appointment_time, expires_at, created_at "
            "FROM appointments "
            f"{where_clause} "
            "ORDER BY appointment_time DESC"
        )
        with self._get_conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def list_valid_appointments_for_doctor(self, doctor_id: str, now_ts: Optional[int] = None) -> List[Dict]:
        doctor_id = (doctor_id or "").strip()
        if not doctor_id:
            return []
        now_ts = int(now_ts or _now_ts())
        query = (
            "SELECT apt_id, doctor_id, patient_id, appointment_time, expires_at, created_at "
            "FROM appointments "
            "WHERE doctor_id = ? AND appointment_time <= ? AND expires_at >= ? "
            "ORDER BY appointment_time DESC"
        )
        with self._get_conn() as conn:
            rows = conn.execute(query, (doctor_id, now_ts, now_ts)).fetchall()
        return [dict(row) for row in rows]

    def list_upcoming_appointments_for_doctor(self, doctor_id: str, now_ts: Optional[int] = None) -> List[Dict]:
        doctor_id = (doctor_id or "").strip()
        if not doctor_id:
            return []
        now_ts = int(now_ts or _now_ts())
        query = (
            "SELECT apt_id, doctor_id, patient_id, appointment_time, expires_at, created_at "
            "FROM appointments "
            "WHERE doctor_id = ? AND appointment_time >= ? "
            "ORDER BY appointment_time ASC"
        )
        with self._get_conn() as conn:
            rows = conn.execute(query, (doctor_id, now_ts)).fetchall()
        return [dict(row) for row in rows]

    def is_upload_allowed(self, doctor_id: str, patient_id: str, now_ts: Optional[int] = None) -> bool:
        doctor_id = (doctor_id or "").strip()
        patient_id = (patient_id or "").strip()
        if not doctor_id or not patient_id:
            return False
        now_ts = int(now_ts or _now_ts())
        query = (
            "SELECT 1 FROM appointments "
            "WHERE doctor_id = ? AND patient_id = ? AND appointment_time <= ? AND expires_at >= ? "
            "LIMIT 1"
        )
        with self._get_conn() as conn:
            row = conn.execute(query, (doctor_id, patient_id, now_ts, now_ts)).fetchone()
        return row is not None


appointments_db = AppointmentDB()
