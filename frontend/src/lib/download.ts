/**
 * Browser file-download helpers (spec 07 sections 3.6, 3.7 and 3.8).
 *
 * Kept in `lib` so every export surface shares one implementation and the
 * object-URL is always revoked.
 */

/** Trigger a browser download of `blob` under `filename`. */
export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(url)
}

/** Download a server-provided file, preferring its filename over the fallback. */
export function saveFile(file: { readonly blob: Blob; readonly filename: string | null }, fallback: string): void {
  downloadBlob(file.blob, file.filename ?? fallback)
}
