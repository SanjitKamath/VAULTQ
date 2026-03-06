# VAULTQ Testing Guide

A step-by-step guide for developers to set up and test the full VAULTQ system end-to-end.

---

## Prerequisites

- **Python 3.11+**
- **Node.js 18+** (for the patient app)
- **OpenSSL** (for TLS certificate generation)

### 1. Create Virtual Environment & Install Dependencies

```bash
cd /path/to/VAULTQ
python3 -m venv .venv
source .venv/bin/activate        # macOS/Linux
# .venv\Scripts\Activate.ps1     # Windows

pip install --upgrade pip
pip install -r security_suite/requirements_security.txt
pip install -r server_app/requirements_server.txt
pip install -r doctor_app/requirements_doctor.txt
```

### 2. Build the Patient App

```bash
cd patient_app
npm install
npm run build
cd ..
```

### 3. Configure Environment Variables

Copy `.env.sample` to `.env` and ensure these values are set:

```bash
VAULTQ_ADMIN_TOKEN=2ee154a7b907f959d2aa03f2e74ce17883eef3b10a6117dff745cf8fe84d70fb
VAULTQ_SERVER_URL=https://127.0.0.1:8080
VAULTQ_PRE_ENROLL_URL=https://127.0.0.1:8081
VAULTQ_ADMIN_SESSION_TTL_SECONDS=3600
VAULTQ_ADMIN_COOKIE_SECURE=1
VAULTQ_MAX_UPLOAD_BYTES=8388608
VAULTQ_PRE_ENROLL_PORT=8081
```

Load them into your shell:

```bash
export $(cat .env | grep -v '#' | xargs)
```

### 4. Generate TLS Certificates

```bash
mkdir -p server_app/storage/certs

openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -keyout server_app/storage/certs/server.key \
  -out server_app/storage/certs/server.crt \
  -subj "/C=IN/O=VaultQ/OU=Dev/CN=127.0.0.1" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

The Hospital Root CA (`hospital_root_ca.pem`) is auto-generated on first server startup.

---

## Starting the System

### Terminal 1 — Start the Server

```bash
source .venv/bin/activate
export $(cat .env | grep -v '#' | xargs)
python -m server_app.main
```

You should see:

```
Starting VAULTQ Server (mTLS) on https://localhost:8080
Starting TLS-only browser/pre-enroll endpoint on https://localhost:8081
```

The server runs two listeners:
- **Port 8080** — mTLS endpoint (doctor uploads, requires client certificate)
- **Port 8081** — TLS-only endpoint (admin panel, pre-enrollment, patient app)

### Terminal 2 — Start the Doctor App

```bash
source .venv/bin/activate
export $(cat .env | grep -v '#' | xargs)
python -m doctor_app.main
```

A Qt login window will appear.

---

## Full End-to-End Testing Flow

### Step 1: Admin — Provision a Doctor

1. Open **`https://localhost:8081/admin`** in your browser
2. Log in with the `VAULTQ_ADMIN_TOKEN` from your `.env` file
3. Click **"Generate Credentials"** and enter a doctor name
4. The system generates a **Doctor ID** (e.g. `doc_0fa080`) and a **temporary password**
5. **Save both** — you'll need them for the doctor app login

### Step 2: Doctor App — First-Time Login & Enrollment

1. In the doctor app login window, enter the **Doctor ID** and **temporary password** from Step 1
2. On first login the app will:
   - Generate a **ML-DSA-65 post-quantum keypair** (identity key)
   - Generate an **ECDSA P-256 keypair** (TLS container key)
   - Create and upload a **Certificate Signing Request (CSR)** to the server
3. The app will begin polling for its certificate — it cannot connect via mTLS yet

> **Important:** Remember or securely store the password. It derives the encryption key for the local identity vault (`doctor_app/storage/keystore/{doctor_id}.vault`). If lost, the admin must use "Recover Access" from the admin panel.

### Step 3: Admin — Issue the Doctor's CA Certificate

1. Go back to the **admin panel** (`https://localhost:8081/admin`)
2. The doctor should now appear in **"pending"** state
3. Click **"ISSUE CA CERT"** for that doctor
4. The server signs an X.509 certificate binding the doctor's ECDSA + ML-DSA keys
5. The doctor app (still polling) will automatically download the certificate

### Step 4: Doctor App — Verify Secure Connection

1. The doctor app should now show **"Secure mTLS Session Established"**
2. If it doesn't connect automatically, close and relaunch the doctor app — log in again with the same credentials (identity loads from the local vault this time)

### Step 5: Admin — Provision a Patient

1. In the admin panel, click **"Generate Credentials"** under the Patients section
2. Enter a patient name
3. The system generates a **Patient ID** (e.g. `pat_53f4f8`) and a **temporary password**
4. Save both for patient app login

### Step 6: Doctor App — Upload a Medical Record

1. In the doctor app, enter the **Patient ID** from Step 5
2. Select a file to upload (PDF, image, or any document)
3. Click **Upload**
4. The app will:
   - Encrypt the file with a random AES-256-GCM Data Encryption Key (DEK)
   - Sign the encrypted payload with the doctor's ML-DSA-65 private key
   - Send the encrypted envelope over mTLS to the server
5. You should see **"Upload success"** in the app

### Step 7: Patient App — View the Record

1. Open **`https://localhost:8081/patient/`** in your browser
2. Log in with the **Patient ID** and **password** from Step 5
3. You should see the uploaded record in the list with the doctor's name and timestamp
4. Click on the record to open it
5. The document should **render in the secure viewer iframe**
6. A verification badge confirms the ML-DSA-65 signature is valid

### Step 8: Verify in Server Logs

Check the server terminal output for:

```
file_recovered=True     # Document was successfully decrypted for the patient
```

For records uploaded **before** the `dek_b64` fix, you'll see `file_recovered=False` — these records will show an "Integrity Verified" fallback instead of the document content. This is expected.

---

## Additional Testing Scenarios

### Password Change (Doctor)

1. Log in to the doctor app
2. Use the password change feature
3. The local identity vault is re-encrypted with the new password-derived key
4. Verify you can log in with the new password

### Certificate Revocation

1. In the admin panel, click **"Revoke"** on a doctor's certificate
2. The doctor app will fail to connect via mTLS on next attempt
3. The admin can issue a new certificate via **"Refresh Cert"**

### Access Recovery (Forgotten Password)

1. In the admin panel, click **"Recover Access"** for the doctor
2. A new temporary password is generated
3. The doctor must delete their local vault file (`doctor_app/storage/keystore/{doctor_id}.vault`) — this forces a new keypair generation on next login
4. The admin must re-issue the CA certificate after the doctor re-enrolls

### Pre-Fix Records (Backwards Compatibility)

Records uploaded before the `dek_b64` fix lack the decryption key in the patient package. When a patient views these:

- The integrity badge still shows **"Integrity Verified"** (signature check passes)
- The document content area shows a fallback message instead of the rendered file
- No errors are thrown

---

## Key Storage Locations

| What | Path |
|------|------|
| Server database | `server_app/storage/hospital_vault.json` |
| Server master key | `server_app/storage/keys/master_key.json` |
| Encrypted patient records | `server_app/storage/vault/<patient_id>/` |
| Server audit log | `server_app/storage/logs/server_audit.log` |
| Integrity event log | `server_app/storage/logs/integrity_events.jsonl` |
| Hospital Root CA cert | `server_app/storage/certs/hospital_root_ca.pem` |
| Doctor identity vault | `doctor_app/storage/keystore/<doctor_id>.vault` |
| Doctor TLS certificate | `doctor_app/storage/keys/doctor_cert.pem` |
| Doctor TLS private key | `doctor_app/storage/keys/doctor_container.key` |
| Doctor audit log | `doctor_app/logs/doctor_audit.log` |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Doctor app: "No secure mTLS session" | Certificate not yet issued | Issue cert from admin panel, then reconnect |
| Doctor app: "Remote end closed connection" | Certificate revoked or expired | Refresh cert from admin panel |
| Doctor app: "CA certificate not found" | Missing `hospital_root_ca.pem` | Copy from `server_app/storage/certs/` to `doctor_app/storage/keys/` |
| Server: `VAULTQ_SERVER_URL and VAULTQ_PRE_ENROLL_URL must differ` | Both URLs point to same port | Use port 8080 for `SERVER_URL`, port 8081 for `PRE_ENROLL_URL` |
| Patient app: document not rendering | Record uploaded before `dek_b64` fix | Upload a new record from the doctor app; old records show fallback |
| Patient app: blank page | Patient app not built | Run `npm run build` in `patient_app/` |
| Server: "Upload too large" | File exceeds 8 MiB limit | Increase `VAULTQ_MAX_UPLOAD_BYTES` or use a smaller file |
| Admin panel: 401 on login | Wrong admin token | Check `VAULTQ_ADMIN_TOKEN` in `.env` matches what you entered |

---

## Clean Reset (Start Fresh)

To wipe all state and start from scratch:

```bash
# Remove server state
rm -f server_app/storage/hospital_vault.json
rm -rf server_app/storage/vault/
rm -rf server_app/storage/keys/
rm -rf server_app/storage/logs/
rm -rf server_app/storage/certs/hospital_root_ca*

# Remove doctor app state
rm -rf doctor_app/storage/keystore/
rm -rf doctor_app/storage/keys/doctor_cert.pem
rm -rf doctor_app/storage/keys/doctor_container.key
rm -rf doctor_app/logs/

# Regenerate server TLS cert
mkdir -p server_app/storage/certs
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -keyout server_app/storage/certs/server.key \
  -out server_app/storage/certs/server.crt \
  -subj "/C=IN/O=VaultQ/OU=Dev/CN=127.0.0.1" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

Then restart the server and follow the full flow from Step 1.
