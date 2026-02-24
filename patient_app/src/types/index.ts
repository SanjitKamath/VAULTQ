export interface LoginRequest {
  id: string
  password: string
}

export interface LoginResponse {
  status: string
  token: string
  name: string
}

export interface RecordSummary {
  record_id: string
  timestamp: number
  patient_id: string
  master_kid: string
  payload_hash: string
  record_hash: string
}

export interface DekVerification {
  wrapped_dek_present: boolean
  nonce_present: boolean
  encrypted_payload_present: boolean
  doctor_signature_present: boolean
  doctor_public_key_present: boolean
}

export interface IntegrityResult {
  record_hash_valid: boolean
  payload_hash_valid: boolean
  master_kid_valid: boolean
  hospital_signature_valid: boolean
  hospital_sig_alg: string
}

export interface RecordDetail {
  record_id: string
  timestamp: number
  patient_id: string
  dek_verification: DekVerification
  integrity: IntegrityResult
  file_content_b64: string | null
  content_type: string
}
