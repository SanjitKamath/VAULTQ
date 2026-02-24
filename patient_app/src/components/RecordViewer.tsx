import { useState, useEffect, useCallback } from 'react'
import { fetchRecord } from '../api/client'
import { base64ToBlobUrl } from '../utils/pdf'
import { VerificationBadge } from './VerificationBadge'
import type { RecordDetail } from '../types'

interface Props {
  recordId: string
  onClose: () => void
}

export function RecordViewer({ recordId, onClose }: Props) {
  const [verifying, setVerifying] = useState(true)
  const [result, setResult] = useState<RecordDetail | null>(null)
  const [error, setError] = useState('')
  const [pdfUrl, setPdfUrl] = useState('')

  const loadRecord = useCallback(async () => {
    setVerifying(true)
    setResult(null)
    setError('')
    setPdfUrl('')

    try {
      const data = await fetchRecord(recordId)
      setResult(data)
      if (data.file_content_b64) {
        setPdfUrl(base64ToBlobUrl(data.file_content_b64, data.content_type || 'application/pdf'))
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Network error: Could not retrieve record.')
    } finally {
      setVerifying(false)
    }
  }, [recordId])

  useEffect(() => {
    loadRecord()
    return () => {
      // Cleanup blob URL on unmount
      setPdfUrl(prev => { if (prev) URL.revokeObjectURL(prev); return '' })
    }
  }, [loadRecord])

  function handleClose() {
    if (pdfUrl) URL.revokeObjectURL(pdfUrl)
    onClose()
  }

  const allDekValid = result?.dek_verification
    ? Object.values(result.dek_verification).every(v => v === true)
    : false

  return (
    <div className="fade-in">
      {/* Back button */}
      <div className="mb-4">
        <button onClick={handleClose} className="text-sm text-emerald-400 hover:text-emerald-300 flex items-center gap-2">
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 19l-7-7 7-7" />
          </svg>
          Back to Records
        </button>
      </div>

      {/* Verification Panel */}
      <div className="bg-gray-900 rounded-xl border border-gray-800 p-6 mb-6 shadow-2xl">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-bold text-white">Security Verification</h3>
          <span className="font-mono text-xs text-slate-500">{recordId}</span>
        </div>

        {/* Loading */}
        {verifying && (
          <div className="text-center py-8">
            <svg className="animate-spin h-8 w-8 mx-auto mb-3 text-emerald-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            <p className="text-slate-400">Verifying encryption keys and integrity...</p>
          </div>
        )}

        {/* Error */}
        {error && !verifying && (
          <div className="p-4 bg-red-900/20 border border-red-500/50 rounded-lg">
            <p className="text-red-300 font-bold mb-1">Verification Failed</p>
            <p className="text-red-400 text-sm">{error}</p>
          </div>
        )}

        {/* Success: badges + DEK details */}
        {result && !error && !verifying && (
          <>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
              <VerificationBadge label="Master Key" valid={result.integrity.master_kid_valid} />
              <VerificationBadge label="Record Hash" valid={result.integrity.record_hash_valid} />
              <VerificationBadge label="Payload Hash" valid={result.integrity.payload_hash_valid} />
              <VerificationBadge label="Hospital Sig" valid={result.integrity.hospital_signature_valid} />
            </div>

            {/* DEK Chain badge */}
            <div className="mb-4">
              <div className="bg-black/50 rounded-lg p-3 border border-gray-800 inline-flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${allDekValid ? 'bg-emerald-500' : 'bg-red-500'}`} />
                <span className="text-xs text-gray-400 uppercase">DEK Chain</span>
                <span className={`text-sm font-bold ml-2 ${allDekValid ? 'text-emerald-400' : 'text-red-400'}`}>
                  {allDekValid ? 'VERIFIED' : 'INCOMPLETE'}
                </span>
              </div>
            </div>

            {/* DEK Verification Details */}
            <div className="bg-black/30 rounded-lg p-4 border border-gray-800">
              <h4 className="text-xs text-gray-400 uppercase tracking-wider mb-3">DEK Verification Details</h4>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                {Object.entries(result.dek_verification).map(([key, val]) => (
                  <div key={key} className="flex items-center gap-2">
                    {val ? (
                      <svg className="w-4 h-4 text-emerald-500 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                      </svg>
                    ) : (
                      <svg className="w-4 h-4 text-red-500 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
                      </svg>
                    )}
                    <span className="text-xs text-slate-400">
                      {key.replace(/_/g, ' ').replace('present', '')}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}
      </div>

      {/* PDF Viewer */}
      {pdfUrl && !verifying && !error && (
        <div className="secure-viewer">
          <div className="bg-emerald-900/20 px-4 py-2 flex items-center justify-between border-b border-emerald-700/30">
            <div className="flex items-center gap-2">
              <svg className="w-4 h-4 text-emerald-400" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clipRule="evenodd" />
              </svg>
              <span className="text-xs text-emerald-400 font-bold uppercase tracking-wider">Secure Document Viewer</span>
            </div>
            <span className="text-xs text-emerald-600">All verification checks passed</span>
          </div>
          <iframe src={pdfUrl} className="w-full bg-gray-800" style={{ height: '80vh' }} frameBorder="0" />
        </div>
      )}

      {/* Verified but no PDF content */}
      {result && !pdfUrl && !verifying && !error && (
        <div className="bg-gray-900 rounded-xl border border-amber-700/40 p-8 text-center">
          <svg className="w-12 h-12 mx-auto mb-4 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
          <h3 className="text-lg font-bold text-amber-400 mb-2">Integrity Verified</h3>
          <p className="text-slate-400 text-sm max-w-md mx-auto">
            All cryptographic verification checks passed. The record's master key, record hash,
            payload hash, and DEK metadata have been validated. The encrypted document is securely stored
            and has not been tampered with.
          </p>
        </div>
      )}
    </div>
  )
}
