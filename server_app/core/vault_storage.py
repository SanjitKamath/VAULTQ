import os
import json
import logging
from abc import ABC, abstractmethod

logger = logging.getLogger("vaultq.storage")


class VaultStorageBackend(ABC):
    """Abstract base class for vault record storage."""

    @abstractmethod
    def save_record(self, patient_id: str, record_id: str, data: dict) -> str:
        """Persist a record and return a storage path/URI for audit logging."""

    @abstractmethod
    def load_record(self, patient_id: str, record_id: str) -> dict:
        """Load a record. Raises FileNotFoundError if it does not exist."""

    @abstractmethod
    def list_records(self, patient_id: str) -> list[str]:
        """Return a sorted list of record IDs (without .json extension) for a patient."""


class LocalVaultStorage(VaultStorageBackend):
    """Stores encrypted records as JSON files on the local filesystem."""

    def __init__(self, base_dir: str | None = None):
        if base_dir is None:
            base_dir = os.path.join(
                os.path.dirname(__file__), "..", "storage", "vault"
            )
        self.base_dir = os.path.abspath(base_dir)
        os.makedirs(self.base_dir, exist_ok=True)
        logger.info("LocalVaultStorage initialized: base_dir=%s", self.base_dir)

    def _patient_dir(self, patient_id: str) -> str:
        safe_id = self._safe(patient_id)
        return os.path.join(self.base_dir, safe_id)

    @staticmethod
    def _safe(value: str) -> str:
        return "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in value)

    def save_record(self, patient_id: str, record_id: str, data: dict) -> str:
        patient_dir = self._patient_dir(patient_id)
        os.makedirs(patient_dir, exist_ok=True)
        file_path = os.path.join(patient_dir, f"{record_id}.json")
        with open(file_path, "w") as f:
            json.dump(data, f, indent=4)
        logger.info("LocalVaultStorage.save_record: %s", file_path)
        return file_path

    def load_record(self, patient_id: str, record_id: str) -> dict:
        file_path = os.path.join(self._patient_dir(patient_id), f"{record_id}.json")
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Record not found: {file_path}")
        with open(file_path, "r") as f:
            return json.load(f)

    def list_records(self, patient_id: str) -> list[str]:
        patient_dir = self._patient_dir(patient_id)
        if not os.path.isdir(patient_dir):
            return []
        record_ids = []
        for fname in sorted(os.listdir(patient_dir)):
            if fname.endswith(".json"):
                record_ids.append(fname.removesuffix(".json"))
        return record_ids


class GCSVaultStorage(VaultStorageBackend):
    """Stores encrypted records as JSON objects in Google Cloud Storage."""

    def __init__(self, bucket_name: str | None = None):
        from google.cloud import storage as gcs_storage

        if bucket_name is None:
            bucket_name = os.environ.get("VAULTQ_GCS_BUCKET")
        if not bucket_name:
            raise ValueError(
                "GCSVaultStorage requires VAULTQ_GCS_BUCKET environment variable "
                "or an explicit bucket_name."
            )
        self._client = gcs_storage.Client()
        self._bucket = self._client.bucket(bucket_name)
        logger.info("GCSVaultStorage initialized: bucket=%s", bucket_name)

    def _blob_name(self, patient_id: str, record_id: str) -> str:
        return f"vault/{patient_id}/{record_id}.json"

    def save_record(self, patient_id: str, record_id: str, data: dict) -> str:
        blob_name = self._blob_name(patient_id, record_id)
        blob = self._bucket.blob(blob_name)
        blob.upload_from_string(
            json.dumps(data, indent=4),
            content_type="application/json",
        )
        uri = f"gs://{self._bucket.name}/{blob_name}"
        logger.info("GCSVaultStorage.save_record: %s", uri)
        return uri

    def load_record(self, patient_id: str, record_id: str) -> dict:
        blob_name = self._blob_name(patient_id, record_id)
        blob = self._bucket.blob(blob_name)
        if not blob.exists():
            raise FileNotFoundError(f"Record not found in GCS: {blob_name}")
        return json.loads(blob.download_as_text())

    def list_records(self, patient_id: str) -> list[str]:
        prefix = f"vault/{patient_id}/"
        record_ids = []
        for blob in self._client.list_blobs(self._bucket, prefix=prefix):
            name = blob.name
            if name.endswith(".json"):
                # Extract record_id from "vault/<pid>/<record_id>.json"
                record_id = name[len(prefix):].removesuffix(".json")
                if record_id:  # skip if empty after stripping
                    record_ids.append(record_id)
        return sorted(record_ids)
