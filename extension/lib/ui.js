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
