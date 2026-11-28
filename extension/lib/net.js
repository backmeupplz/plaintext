// The only way Plaintext's core (Rust, compiled to WebAssembly) reaches a
// server. It hands over a request and gets [status, bytes] back; every key,
// seal and check stays in Rust.
const LIMIT = 128 << 20 // as the CLI's response cap
const TIMEOUT = 120_000

export async function send(method, url, token, body) {
  const headers = { 'content-type': 'application/json' }
  if (token) headers.authorization = `Bearer ${token}`
  const res = await fetch(url, {
    method,
    headers,
    body,
    // A server can't bounce a request (and its token) to another host.
    redirect: 'error',
    credentials: 'omit',
    cache: 'no-store',
    referrerPolicy: 'no-referrer',
    signal: AbortSignal.timeout(TIMEOUT),
  })
  const parts = []
  let size = 0
  const reader = res.body?.getReader()
  while (reader) {
    const { done, value } = await reader.read()
    if (done) break
    size += value.length
    if (size > LIMIT) {
      reader.cancel()
      throw new Error('the server sent more than any vault holds')
    }
    parts.push(value)
  }
  const out = new Uint8Array(size)
  let at = 0
  for (const p of parts) {
    out.set(p, at)
    at += p.length
  }
  return [res.status, out]
}
