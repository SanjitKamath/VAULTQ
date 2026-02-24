import { useState } from 'react'
import { useAuth } from '../hooks/useAuth'
import { RecordsList } from './RecordsList'
import { RecordViewer } from './RecordViewer'

export function DashboardPage() {
  const { patientName, patientId, logout } = useAuth()
  const [currentView, setCurrentView] = useState<'list' | 'viewer'>('list')
  const [activeRecordId, setActiveRecordId] = useState('')

  function openRecord(recordId: string) {
    setActiveRecordId(recordId)
    setCurrentView('viewer')
  }

  function closeViewer() {
    setCurrentView('list')
    setActiveRecordId('')
  }

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="bg-slate-900 border-b border-slate-800 px-6 py-4 flex justify-between items-center">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded bg-gradient-to-br from-emerald-500 to-cyan-400 flex items-center justify-center shadow-lg shadow-emerald-500/20">
            <span className="font-bold text-white tracking-tighter">VQ</span>
          </div>
          <h1 className="text-xl font-bold tracking-wide text-white">
            VaultQ <span className="text-slate-500 font-light">Patient Portal</span>
          </h1>
        </div>
        <div className="flex items-center gap-4 text-sm">
          <span className="text-slate-400">
            Welcome, <span className="text-emerald-400 font-semibold">{patientName}</span>
          </span>
          <span className="text-slate-600">|</span>
          <span className="font-mono text-xs text-slate-500">{patientId}</span>
          <button
            onClick={logout}
            className="ml-4 text-xs text-red-400 hover:text-red-300 font-bold border border-red-900 px-3 py-1 rounded hover:border-red-700 transition"
          >
            LOGOUT
          </button>
        </div>
      </header>

      {/* Main */}
      <main className="max-w-7xl mx-auto p-6 w-full flex-1">
        {currentView === 'list' && <RecordsList onOpenRecord={openRecord} />}
        {currentView === 'viewer' && <RecordViewer recordId={activeRecordId} onClose={closeViewer} />}
      </main>

      {/* Footer */}
      <footer className="bg-slate-900 border-t border-slate-800 py-3 text-center text-xs text-slate-600">
        VaultQ Secure Medical Record System &mdash; AES-256-GCM + ML-DSA-65 Post-Quantum Encryption
      </footer>
    </div>
  )
}
