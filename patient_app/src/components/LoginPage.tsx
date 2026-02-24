import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import { login } from '../api/client'

export function LoginPage() {
  const [patientId, setPatientId] = useState('')
  const [password, setPassword] = useState('')
  const [errorMsg, setErrorMsg] = useState('')
  const [loading, setLoading] = useState(false)
  const { setSession, isAuthenticated } = useAuth()
  const navigate = useNavigate()

  // Redirect if already logged in
  if (isAuthenticated) {
    navigate('/patient/dashboard', { replace: true })
    return null
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setErrorMsg('')
    setLoading(true)
    try {
      const data = await login(patientId.trim(), password)
      setSession(data.token, data.name, patientId.trim())
      navigate('/patient/dashboard')
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Authentication failed.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="w-full max-w-md fade-in">
        {/* Logo + Title */}
        <div className="text-center mb-8">
          <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-emerald-500 to-cyan-400 flex items-center justify-center shadow-lg shadow-emerald-500/20 mx-auto mb-4 pulse-ring">
            <span className="font-bold text-white text-2xl tracking-tighter">VQ</span>
          </div>
          <h1 className="text-3xl font-bold text-white">VaultQ</h1>
          <p className="text-slate-400 mt-1">Patient Secure Portal</p>
        </div>

        {/* Login Card */}
        <div className="bg-gray-900 p-8 rounded-2xl border border-gray-800 shadow-2xl">
          <h2 className="text-xl font-bold text-emerald-400 mb-6">Sign In</h2>

          {errorMsg && (
            <div className="mb-4 p-3 bg-red-900/30 border border-red-500/50 rounded-lg text-red-300 text-sm">
              {errorMsg}
            </div>
          )}

          <form onSubmit={handleSubmit}>
            <div className="mb-5">
              <label className="block text-xs text-gray-400 uppercase tracking-wider mb-2">Patient ID</label>
              <input
                type="text"
                value={patientId}
                onChange={e => setPatientId(e.target.value)}
                placeholder="pat_xxxxxx"
                required
                className="w-full bg-black border border-gray-700 p-3 rounded-lg text-white font-mono focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 outline-none transition"
              />
            </div>
            <div className="mb-6">
              <label className="block text-xs text-gray-400 uppercase tracking-wider mb-2">Password</label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="Enter your password"
                required
                className="w-full bg-black border border-gray-700 p-3 rounded-lg text-white focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 outline-none transition"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-emerald-600 py-3 rounded-lg font-bold text-white hover:bg-emerald-500 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Authenticating...' : 'Access Secure Portal'}
            </button>
          </form>
        </div>

        <p className="text-center text-slate-600 text-xs mt-6">
          End-to-end encrypted medical record portal
        </p>
      </div>
    </div>
  )
}
