// Small helpers shared by the popup and the settings page.
import { icon } from './icons.js'

export { icon }

/** Ask the background. Rejects with an Error whose name is the core's code. */
export async function ask(action, data = {}) {
  const r = await chrome.runtime.sendMessage({ action, ...data })
  if (!r) throw Object.assign(new Error('Plaintext is restarting. Try again.'), { name: 'busy' })
  if (r.error) throw Object.assign(new Error(r.error.message), { name: r.error.name })
  return r.ok
}

export function el(tag, props = {}, ...kids) {
  const e = document.createElement(tag)
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue
    if (k === 'class') e.className = v
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v)
    else e.setAttribute(k, v === true ? '' : v)
  }
  e.append(...kids.flat().filter((k) => k != null && k !== false))
  return e
}

/** An icon button; the label is what screen readers say. */
export const iconButton = (name, label, onclick, cls = 'icon-btn') => el('button', { class: cls, type: 'button', 'aria-label': label, title: label, onclick }, icon(name))

/** People-facing wording for what went wrong. */
export function explain(e) {
  switch (e?.name) {
    case 'network':
      return "Couldn't reach your Plaintext server. Check your connection, then try again."
    case 'tampered':
      return e.message?.includes('match') ? e.message : "That password didn't match. Check it, then try again. If you changed your password on another device, add this account again in Settings."
    case 'signed_out':
      return e.message?.startsWith('Your session ended') ? e.message : 'Your session ended. Unlock Plaintext again.'
    case 'bad_secret_key':
      return "That Secret Key doesn't look right. It starts with A1- and is on your Emergency Kit."
    default:
      return e?.message || 'Something went wrong. Try again.'
  }
}

/** A sync problem for people: without the CLI hint it can end with (the
 *  popup has its own Leave). */
export function problemText(text) {
  return text.split(' (plaintext ')[0]
}

/** A tile with the title's first letter on a tint from the title (never a favicon). */
export function monogram(title) {
  let h = 0
  for (const c of title || '?') h = (h * 31 + c.codePointAt(0)) % 360
  const t = el('span', { class: 'tile', 'aria-hidden': 'true' }, [...(title || '?').trim()][0]?.toUpperCase() ?? '?')
  t.style.setProperty('--hue', h) // CSSOM, which the strict CSP allows (style attributes it doesn't)
  return t
}

const CLEAR_S = 90
/** Copy, and have the background clear the clipboard after 90 seconds. */
export async function copy(text, say) {
  try {
    await navigator.clipboard.writeText(text)
    await ask('copied')
    say(`Copied. Clears in ${CLEAR_S} s.`)
    return true
  } catch {
    say("Couldn't copy. Select the text and copy it yourself.")
    return false
  }
}

/** A sign-in waiting for the account's security key (DESIGN "Signing in with a
 *  security key"). The extension asks the key itself, through WebAuthn for the
 *  server's own RP ID, so a look-alike site can't get its answer. Browsers that
 *  won't let it fall back to the server's approval page: touch the key there,
 *  then continue here. Or type a recovery code. `done(result)` runs once signed in. */
export function keyStep(w, done) {
  const host = new URL(w.server).host
  const who = w.key.startsWith('new@') ? `Your account on ${host}` : `${w.key.split('@')[0]} on ${host}`
  const code = el('input', { type: 'text', id: 'recovery', class: 'mono', autocomplete: 'off', spellcheck: 'false', placeholder: 'xxxxx-xxxxx-xxxxx-xxxxx' })
  const err = el('p', { class: 'error', role: 'alert' })
  const go = el('button', { type: 'submit' }, 'Continue')
  const finish = async (data, btn) => {
    btn.disabled = true
    err.textContent = ''
    try {
      done(await ask('finishKey', { key: w.key, ...data }))
    } catch (x) {
      err.textContent = explain(x)
      // Not approved on the page yet, or the server refused the key's answer: the page is the way on.
      if (x?.name === 'not_approved' || x?.name === 'key_refused') page.hidden = false
    } finally {
      btn.disabled = false
    }
  }
  const page = el(
    'div',
    { hidden: true },
    el('button', { type: 'button', onclick: () => chrome.tabs.create({ url: w.page }) }, 'Approve on my server’s page instead'),
    el('p', { class: 'muted small-text' }, 'That page asks your key on your server’s own site. Touch the key there, then come back here and continue. Only approve a sign-in you just started yourself.'),
  )
  const fallBack = (why) => {
    page.hidden = false
    err.textContent = why
  }
  const touch = el(
    'button',
    {
      class: 'primary',
      type: 'button',
      onclick: async () => {
        // A popup closes when the browser's security key prompt takes the focus: ask from a tab.
        if (location.pathname.endsWith('/popup.html')) {
          chrome.tabs.create({ url: chrome.runtime.getURL(`setup.html#signin=${encodeURIComponent(w.key)}`) })
          return window.close()
        }
        let assertion
        try {
          assertion = await touchKey(w.request)
        } catch (x) {
          return fallBack(x?.name === 'NotAllowedError' ? 'Your security key didn’t answer. Try again, or approve on your server’s page.' : 'This browser won’t ask your security key for this server here.')
        }
        await finish({ assertion }, touch)
      },
    },
    icon('key-round'),
    'Use my security key',
  )
  const usable = w.request?.allow?.length > 0
  if (!usable) page.hidden = false
  return el(
    'form',
    { class: 'key-step', onsubmit: (e) => (e.preventDefault(), finish({ recovery: code.value.trim() }, go)) },
    el('p', {}, `${who} needs your security key to sign in on this browser. After that, this browser is remembered.`),
    usable && touch,
    page,
    el('label', { for: 'recovery' }, 'Or use a recovery code'),
    code,
    err,
    go,
  )
}

const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
const bytes = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0))

/** The key's answer to a sign-in's `request` ({rpId, challenge, allow}), as the server takes it. */
async function touchKey(req) {
  const cred = await navigator.credentials.get({
    publicKey: {
      rpId: req.rpId,
      challenge: bytes(req.challenge),
      allowCredentials: req.allow.map((id) => ({ type: 'public-key', id: bytes(id) })),
      userVerification: 'discouraged',
      timeout: 120_000,
    },
  })
  const r = cred.response
  return { id: b64(cred.rawId), client_data: b64(r.clientDataJSON), auth_data: b64(r.authenticatorData), signature: b64(r.signature) }
}
