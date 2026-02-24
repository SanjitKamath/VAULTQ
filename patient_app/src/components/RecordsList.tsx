import { useState, useEffect, useCallback } from 'react'
import { fetchRecords } from '../api/client'
import { formatTimestamp } from '../utils/date'
import type { RecordSummary } from '../types'

interface Props {
  onOpenRecord: (recordId: string) => void
}

export function RecordsList({ onOpenRecord }: Props) {
  const [records, setRecords] = useState<RecordSummary[]>([])
  const [loading, setLoading] = useState(true)

  const loadRecords = useCallback(async () => {
    setLoading(true)
    try {
      const data = await fetchRecords()
      setRecords(data)
    } catch (err) {
      console.error('Failed to load records:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadRecords() }, [loadRecords])

  return (
    <div className="fade-in">
      <div className="bg-gray-900 rounded-xl border border-gray-800 overflow-hidden shadow-2xl">
        <div className="p-6 border-b border-gray-800 flex justify-between items-center">
          <div>
            <h2 className="text-xl font-bold text-white">My Medical Records</h2>
            <p className="text-sm text-slate-500 mt-1">Documents sent by your healthcare provider</p>
          </div>
          <button onClick={loadRecords} className="text-sm text-emerald-500 hover:underline">Refresh</button>
        </div>

        {/* Loading */}
        {loading && (
          <div className="py-16 text-center text-slate-500">
            <svg className="animate-spin h-8 w-8 mx-auto mb-3 text-emerald-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            Loading records...
          </div>
        )}

        {/* Records Table */}
        {!loading && (
          <table className="w-full text-left">
            <thead className="bg-black/50 text-gray-400 uppercase text-xs">
              <tr>
                <th className="py-4 px-4">Record ID</th>
                <th className="py-4 px-4">Date</th>
                <th className="py-4 px-4">Encryption</th>
                <th className="py-4 px-4">Integrity</th>
                <th className="py-4 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {records.map(rec => (
                <tr
                  key={rec.record_id}
                  onClick={() => onOpenRecord(rec.record_id)}
                  className="border-b border-gray-800 hover:bg-gray-800/30 transition cursor-pointer"
                >
                  <td className="py-4 px-4 font-mono text-emerald-400 text-sm">{rec.record_id}</td>
                  <td className="py-4 px-4 text-sm">{formatTimestamp(rec.timestamp)}</td>
                  <td className="py-4 px-4">
                    <span className="px-2 py-1 rounded text-xs font-bold bg-emerald-900/30 text-emerald-400">
                      AES-256-GCM
                    </span>
                  </td>
                  <td className="py-4 px-4">
                    <span className={`px-2 py-1 rounded text-xs font-bold ${rec.record_hash ? 'bg-blue-900/30 text-blue-400' : 'bg-red-900/30 text-red-400'}`}>
                      {rec.record_hash ? 'HASH PRESENT' : 'MISSING'}
                    </span>
                  </td>
                  <td className="py-4 px-4 text-right">
                    <button className="bg-emerald-600 px-4 py-2 rounded-lg text-xs font-bold hover:bg-emerald-500 transition">
                      VIEW DOCUMENT
                    </button>
                  </td>
                </tr>
              ))}
              {records.length === 0 && (
                <tr>
                  <td colSpan={5} className="py-16 text-center text-slate-500 italic">
                    No medical records found. Your doctor has not sent any documents yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
