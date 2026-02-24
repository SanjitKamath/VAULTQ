interface Props {
  label: string
  valid: boolean
}

export function VerificationBadge({ label, valid }: Props) {
  return (
    <div className="bg-black/50 rounded-lg p-3 border border-gray-800">
      <div className="flex items-center gap-2 mb-1">
        <div className={`w-2 h-2 rounded-full ${valid ? 'bg-emerald-500' : 'bg-red-500'}`} />
        <span className="text-xs text-gray-400 uppercase">{label}</span>
      </div>
      <span className={`text-sm font-bold ${valid ? 'text-emerald-400' : 'text-red-400'}`}>
        {valid ? 'VERIFIED' : 'FAILED'}
      </span>
    </div>
  )
}
