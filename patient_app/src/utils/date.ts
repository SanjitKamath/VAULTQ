export function formatTimestamp(ts: number | null | undefined): string {
  if (!ts) return '\u2014'
  return new Date(ts * 1000).toLocaleString()
}
