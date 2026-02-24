import type { LoginResponse, RecordSummary, RecordDetail } from '../types'

function getToken(): string {
  return sessionStorage.getItem('vaultq_patient_token') || ''
}

function authHeaders(): Record<string, string> {
  return { 'x-patient-token': getToken() }
}

async function handleResponse<T>(resp: Response): Promise<T> {
  if (resp.status === 401) {
    sessionStorage.removeItem('vaultq_patient_token')
    sessionStorage.removeItem('vaultq_patient_name')
    sessionStorage.removeItem('vaultq_patient_id')
    window.location.href = '/patient'
    throw new Error('Session expired')
  }
  let data: any = null
  try {
    data = await resp.json()
  } catch {
    data = null
  }
  if (!resp.ok) {
    throw new Error((data && (data.detail || data.message)) || `Request failed (${resp.status})`)
  }
  return data as T
}

export async function login(id: string, password: string): Promise<LoginResponse> {
  const resp = await fetch('/api/patient/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ id, password }),
  })
  let data: any = null
  try {
    data = await resp.json()
  } catch {
    data = null
  }
  if (!resp.ok) {
    throw new Error((data && (data.detail || data.message)) || `Authentication failed (${resp.status})`)
  }
  return data as LoginResponse
}

export async function fetchRecords(): Promise<RecordSummary[]> {
  const resp = await fetch('/api/patient/records', { headers: authHeaders() })
  return handleResponse<RecordSummary[]>(resp)
}

export async function fetchRecord(recordId: string): Promise<RecordDetail> {
  const resp = await fetch(`/api/patient/records/${recordId}`, { headers: authHeaders() })
  return handleResponse<RecordDetail>(resp)
}
