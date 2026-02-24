export function base64ToBlobUrl(b64: string, contentType = 'application/pdf'): string {
  const binaryStr = atob(b64)
  const bytes = new Uint8Array(binaryStr.length)
  for (let i = 0; i < binaryStr.length; i++) {
    bytes[i] = binaryStr.charCodeAt(i)
  }
  const blob = new Blob([bytes], { type: contentType })
  return URL.createObjectURL(blob)
}
