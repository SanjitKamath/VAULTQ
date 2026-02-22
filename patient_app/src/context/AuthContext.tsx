import { createContext, useState, useCallback, type ReactNode } from 'react'

interface AuthState {
  token: string | null
  patientName: string
  patientId: string
  isAuthenticated: boolean
  setSession: (token: string, name: string, id: string) => void
  logout: () => void
}

export const AuthContext = createContext<AuthState>({
  token: null,
  patientName: '',
  patientId: '',
  isAuthenticated: false,
  setSession: () => {},
  logout: () => {},
})

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(
    () => sessionStorage.getItem('vaultq_patient_token')
  )
  const [patientName, setPatientName] = useState(
    () => sessionStorage.getItem('vaultq_patient_name') || ''
  )
  const [patientId, setPatientId] = useState(
    () => sessionStorage.getItem('vaultq_patient_id') || ''
  )

  const setSession = useCallback((t: string, name: string, id: string) => {
    sessionStorage.setItem('vaultq_patient_token', t)
    sessionStorage.setItem('vaultq_patient_name', name)
    sessionStorage.setItem('vaultq_patient_id', id)
    setToken(t)
    setPatientName(name)
    setPatientId(id)
  }, [])

  const logout = useCallback(() => {
    sessionStorage.removeItem('vaultq_patient_token')
    sessionStorage.removeItem('vaultq_patient_name')
    sessionStorage.removeItem('vaultq_patient_id')
    setToken(null)
    setPatientName('')
    setPatientId('')
  }, [])

  return (
    <AuthContext.Provider value={{
      token,
      patientName,
      patientId,
      isAuthenticated: !!token,
      setSession,
      logout,
    }}>
      {children}
    </AuthContext.Provider>
  )
}
