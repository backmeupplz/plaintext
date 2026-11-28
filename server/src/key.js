// The approval page (DESIGN "Signing in with a security key"): asks the security
// key to approve one pending sign-in for this server's own host, then hands its
// answer to the server. The app that started the sign-in finishes it.
const what = document.getElementById('what')
const go = document.getElementById('go')
const challenge = location.hash.slice(1)
const bytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
const hex = (h) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16))
const say = (text) => { what.textContent = text }

async function load() {
  if (!/^[0-9a-f]{64}$/.test(challenge)) return say('This link is incomplete. Start signing in again in Plaintext.')
  if (!window.PublicKeyCredential) return say("This browser can't use security keys. Open this page in another one, or use a recovery code in Plaintext.")
  const r = await fetch(`approve/${challenge}`, { cache: 'no-store' })
  if (!r.ok) return say(await r.text())
  const a = await r.json()
  const keys = a.keys.filter((k) => k.rp_id === location.hostname)
  if (!keys.length) return say(`None of ${a.username}'s security keys was added for ${location.hostname}. Sign in at the address you added them for, or use a recovery code.`)
  const device = a.device.length > 60 ? `${a.device.slice(0, 60)}…` : a.device
  say(`${a.username} is signing in on a device that calls itself “${device}”. Plug in or hold your security key near this device, then continue.`)
  go.hidden = false
  go.onclick = () => approve(keys).catch((e) => { say(`That didn't work (${e.message}). Try again, or use a recovery code in Plaintext.`); go.hidden = false })
}

async function approve(keys) {
  go.hidden = true
  say('Touch your security key.')
  const c = await navigator.credentials.get({
    publicKey: {
      challenge: hex(challenge),
      rpId: location.hostname,
      allowCredentials: keys.map((k) => ({ type: 'public-key', id: bytes(k.id) })),
      userVerification: 'discouraged',
      timeout: 120000,
    },
  })
  const r = await fetch(`approve/${challenge}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      id: b64(c.rawId),
      client_data: b64(c.response.clientDataJSON),
      auth_data: b64(c.response.authenticatorData),
      signature: b64(c.response.signature),
    }),
  })
  if (!r.ok) throw new Error(await r.text())
  say('Approved. Go back to Plaintext to finish signing in; you can close this page.')
  document.getElementById('note').hidden = true
}

load().catch((e) => say(`Couldn't load this sign-in (${e.message}). Start again in Plaintext.`))
