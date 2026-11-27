// Share-link viewer. The link is https://getplaintext.org/s/#<server>/<id>/<key>:
// the fragment never leaves this browser. We fetch the sealed blob from <server>
// and decrypt it with Plaintext's own core, compiled to WebAssembly.
import init, { open_link, totp } from './plaintext_wasm.js'

const main = document.getElementById('main')
const live = document.getElementById('live')

function el(tag, props = {}, ...kids) {
  const e = document.createElement(tag)
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') e.className = v
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v)
    else e.setAttribute(k, v)
  }
  e.append(...kids.filter((k) => k != null && k !== false))
  return e
}

const ICONS = {
  copy: ['M10 8h10a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H10a2 2 0 0 1-2-2V10a2 2 0 0 1 2-2z', 'M4 16a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2'],
  check: ['M20 6 9 17l-5-5'],
  eye: ['M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z', 'M9 12a3 3 0 1 0 6 0 3 3 0 1 0-6 0'],
  eyeOff: ['M10.7 5.1A10 10 0 0 1 12 5c6.4 0 10 7 10 7a17 17 0 0 1-2.2 3.1', 'M6.6 6.6C3.7 8.4 2 12 2 12s3.6 7 10 7a9.7 9.7 0 0 0 5.4-1.6', 'M9.9 9.9a3 3 0 0 0 4.2 4.2', 'M2 2l20 20'],
  open: ['M15 3h6v6', 'M10 14 21 3', 'M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6'],
}
const NS = 'http://www.w3.org/2000/svg'
function icon(name) {
  const svg = document.createElementNS(NS, 'svg')
  svg.setAttribute('viewBox', '0 0 24 24')
  svg.setAttribute('aria-hidden', 'true')
  for (const d of ICONS[name]) {
    const p = document.createElementNS(NS, 'path')
    p.setAttribute('d', d)
    svg.append(p)
  }
  return svg
}

function state(kind, title, ...lines) {
  const h = el('h1', { tabindex: '-1' }, title)
  main.replaceChildren(el('div', { class: `state ${kind}` }, h, ...lines.map((l) => (typeof l === 'string' ? el('p', {}, l) : l))))
  announce('') // the focused heading speaks for itself
  h.focus()
}
function loading() {
  main.replaceChildren(el('p', { class: 'loading' }, 'Opening the link…'))
  announce('Opening the link…', true) // already on screen, so for screen readers only
}

// <server> may itself contain slashes, so the id and key are taken from the right.
function parseLink(hash) {
  const m = /^#(https?:\/\/.+?)\/+([0-9a-f]{32})\/([0-9a-f]{64})$/i.exec(hash)
  if (!m) return null
  try {
    const server = new URL(m[1])
    if (server.search || server.hash || server.username || server.password) return null
    const id = m[2].toLowerCase()
    return { server, id, key: m[3], api: `${server.origin}${server.pathname.replace(/\/+$/, '')}/v1/links/${id}` }
  } catch {
    return null
  }
}

async function start() {
  const link = parseLink(location.hash)
  if (!link) {
    return state('bad', 'This link is incomplete', 'Everything after the # in the link is needed to open it. Ask the sender to send you the whole link again.')
  }
  loading()
  if (typeof WebAssembly !== 'object') {
    return state('bad', "This browser can't open the link", "Opening it takes WebAssembly, which this browser has turned off or doesn't support. Try another browser.")
  }
  try {
    await init()
  } catch (e) {
    if (e instanceof WebAssembly.CompileError) {
      return state('bad', "This browser can't open the link", 'Opening it takes a newer browser. Update this one, or try another browser.')
    }
    // Nothing has been fetched from the link's server yet, so reloading is safe.
    return state('bad', "This page didn't load fully", 'Part of it failed to download. Check your connection, then try again.',
      el('button', { class: 'btn', type: 'button', onclick: () => location.reload() }, 'Try again'))
  }
  const host = link.server.host
  const name = link.server.hostname
  // Browsers treat these as secure, so a secure page may fetch them over plain HTTP.
  const local = name === 'localhost' || name === '[::1]' || name.endsWith('.localhost') || /^127\.\d+\.\d+\.\d+$/.test(name)
  if (location.protocol === 'https:' && link.server.protocol === 'http:' && !local) {
    return state('bad', "This link's server doesn't use HTTPS", `Browsers don't let a secure page fetch from ${host} over plain HTTP. Ask the sender to put their Plaintext server behind HTTPS and make a new link.`)
  }
  // Wait for a tap: link scanners and previews that run scripts would otherwise
  // use up a one-view link before its recipient sees it.
  state('ready', 'Someone shared an item with you', `It's stored encrypted on ${host} and is decrypted here, in your browser. Some links open only once, so show it when you're ready to copy what you need.`,
    el('button', { class: 'btn', type: 'button', onclick: () => show(link) }, 'Show the item'))
}

let busy = false
async function show(link) {
  if (busy) return
  busy = true
  loading()
  try {
    await fetchAndRender(link)
  } finally {
    busy = false
  }
}

async function fetchAndRender(link) {
  const host = link.server.host
  const retry = el('button', { class: 'btn', type: 'button', onclick: () => show(link) }, 'Try again')
  // Each successful fetch uses up one view, so it happens only on a tap.
  let res, body
  try {
    res = await fetch(link.api, { cache: 'no-store', credentials: 'omit', signal: AbortSignal.timeout?.(30000) })
  } catch (e) {
    if (e?.name === 'TimeoutError') {
      return state('bad', "The server didn't answer in time", `${host} took too long to answer. Try again; if the link could be opened only once, you may need a new one from the sender.`, retry)
    }
    return state('bad', "Couldn't reach the server", `${host} didn't answer. Check your connection, then try again.`, retry)
  }
  if (res.status === 404) {
    return state('gone', 'This link has expired or was already used', 'Links stop working at their expiry date, and some can be opened only once. Ask the sender for a new link.')
  }
  if (!res.ok) {
    return state('bad', "The server couldn't open this link", `${host} answered with an error (${res.status}). Try again in a moment, or ask the sender for a new link.`, retry)
  }
  try {
    body = await res.text()
  } catch {
    return state('bad', 'The connection dropped', `${host} started answering, but the answer didn't arrive in full. Try again; if the link could be opened only once, you may need a new one from the sender.`, retry)
  }
  let blob
  try {
    blob = JSON.parse(body)
  } catch {}
  if (typeof blob !== 'string') {
    return state('bad', "The server's answer wasn't a shared item", `${host} answered with something else, perhaps a sign-in page on this network. Try again on another network, or ask the sender for a new link.`, retry)
  }
  let item
  try {
    item = JSON.parse(open_link(link.id, blob, link.key))
  } catch (e) {
    if (e?.message === 'unreadable') return unreadable()
    return state('bad', "This link couldn't be decrypted", "The key in the link doesn't match what the server sent, so the link was mistyped or the stored item was altered. Nothing is shown. Ask the sender for a new link.")
  }
  try {
    render(item)
  } catch {
    unreadable()
  }
}
const unreadable = () => state('bad', "This item couldn't be shown", "It was decrypted, but this page couldn't display it. Ask the sender to share it another way.")

// ---------- The item ----------

const KINDS = {
  login: 'Login', password: 'Password', note: 'Secure note', card: 'Credit card', identity: 'Identity', document: 'Document',
  bank: 'Bank account', database: 'Database', server: 'Server', ssh_key: 'SSH key', api_credential: 'API credential',
  wifi: 'Wi-Fi', passport: 'Passport', license: "Driver's license", membership: 'Membership', crypto_wallet: 'Crypto wallet',
}
const kindName = (k) => (Object.prototype.hasOwnProperty.call(KINDS, k) ? KINDS[k] : k ? k[0].toUpperCase() + k.slice(1).replaceAll('_', ' ') : 'Item')

let liveTimer
function announce(text, quiet = false) {
  clearTimeout(liveTimer)
  live.classList.toggle('quiet', quiet)
  live.textContent = text
  liveTimer = setTimeout(() => (live.textContent = ''), 2500)
}

async function copy(text, button) {
  let done = false
  try {
    await navigator.clipboard.writeText(text)
    done = true
  } catch {
    const t = el('textarea', { readonly: '', 'aria-hidden': 'true' })
    t.value = text
    document.body.append(t)
    t.select()
    try {
      done = document.execCommand('copy')
    } catch {}
    t.remove()
  }
  if (!done) return announce("Couldn't copy. Show it if it's hidden, then select it and copy it by hand.")
  announce('Copied')
  button.classList.add('done')
  button.replaceChildren(icon('check'))
  setTimeout(() => {
    button.classList.remove('done')
    button.replaceChildren(icon('copy'))
  }, 1500)
}

function copyButton(text, what) {
  const b = el('button', { class: 'icon', type: 'button', 'aria-label': `Copy ${what}`, title: `Copy ${what}` }, icon('copy'))
  b.addEventListener('click', () => copy(typeof text === 'function' ? text() : text, b))
  return b
}

// A drag-select inside the value also fires click: let the reader copy just the selection.
function clickCopy(button) {
  return () => { if (!getSelection().toString()) button.click() }
}

function row(label, value, ...actions) {
  return el('div', { class: 'row' }, el('div', { class: 'body' }, el('div', { class: 'label' }, label), value), ...actions)
}

function textRow(label, text) {
  const copyB = copyButton(text, label.toLowerCase())
  const v = el('div', { class: 'value copyable', onclick: clickCopy(copyB) }, text)
  return row(label, v, copyB)
}

function secretRow(label, secret) {
  const dots = '•'.repeat(10) // the same for every secret, so it hides the length
  const v = el('span', { class: 'value mono secret copyable' }, dots)
  let shown = false
  // A toggle keeps one label; aria-pressed carries the state.
  const eye = el('button', { class: 'icon', type: 'button', 'aria-label': `Show ${label.toLowerCase()}`, title: `Show ${label.toLowerCase()}` })
  const sync = () => {
    v.textContent = shown ? secret : dots
    eye.setAttribute('aria-pressed', String(shown))
    eye.replaceChildren(icon(shown ? 'eyeOff' : 'eye'))
  }
  eye.addEventListener('click', () => {
    shown = !shown
    sync()
  })
  sync()
  const copyB = copyButton(secret, label.toLowerCase())
  v.addEventListener('click', clickCopy(copyB))
  return row(label, v, eye, copyB)
}

function urlRow(label, url) {
  const href = /^https?:\/\//i.test(url) ? url : /^[\w.-]+\.[a-z]{2,}([/:?#]|$)/i.test(url) ? `https://${url}` : null
  if (!href) return textRow(label, url)
  const open = { href, target: '_blank', rel: 'noopener noreferrer' }
  return row(label, el('a', { class: 'value', ...open }, url), el('a', { class: 'icon', ...open, 'aria-label': `Open ${url}`, title: 'Open' }, icon('open')), copyButton(url, 'link'))
}

const otpRows = []
function otpRow(label, spec) {
  if (!totp(spec, Date.now() / 1000)) return secretRow(label, spec)
  const period = JSON.parse(totp(spec, 0))[1] // at t = 0 the whole period is left
  const C = 2 * Math.PI * 11
  const ring = document.createElementNS(NS, 'svg')
  ring.setAttribute('class', 'ring')
  ring.setAttribute('viewBox', '0 0 28 28')
  ring.setAttribute('aria-hidden', 'true')
  const circle = (cls) => {
    const c = document.createElementNS(NS, 'circle')
    for (const [k, v] of Object.entries({ class: cls, cx: 14, cy: 14, r: 11, 'stroke-dasharray': C })) c.setAttribute(k, v)
    ring.append(c)
    return c
  }
  circle('track')
  const left = circle('left')
  const code = el('span', { class: 'otp copyable' })
  const next = el('div', { class: 'next' })
  const secsLeft = el('span', {})
  const tick = () => {
    const now = Date.now() / 1000
    const [c, secs] = JSON.parse(totp(spec, now))
    code.textContent = c.length === 6 ? `${c.slice(0, 3)} ${c.slice(3)}` : c
    left.setAttribute('stroke-dashoffset', String(C * (1 - secs / period)))
    ring.classList.toggle('ending', secs <= 5)
    next.textContent = secs <= 5 ? `Next: ${JSON.parse(totp(spec, now + secs))[0]}` : ''
    secsLeft.textContent = `${secs}s left`
  }
  otpRows.push(tick)
  tick()
  // Fresh on copy: background tabs throttle the tick, so the shown code can be stale.
  const copyB = copyButton(() => JSON.parse(totp(spec, Date.now() / 1000))[0], 'one-time code')
  code.addEventListener('click', clickCopy(copyB))
  const out = document.createDocumentFragment()
  // The seed too, so the recipient can add it to their own authenticator.
  const [what, seed] = setupKey(spec)
  out.append(row(el('span', {}, `${label} · `, secsLeft), el('div', {}, code, next), ring, copyB),
    secretRow(label === 'One-time code' ? what : `${label} ${what.toLowerCase()}`, seed))
  return out
}

// Authenticators take a bare base32 secret as a "setup key"; an otpauth:// link
// is reduced to that unless it sets non-default digits, period or algorithm.
function setupKey(spec) {
  if (!/^otpauth:/i.test(spec.trim())) return ['Setup key', spec]
  try {
    const p = new Map([...new URL(spec.trim()).searchParams].map(([k, v]) => [k.toLowerCase(), v]))
    const plain = (p.get('digits') || '6') === '6' && (p.get('period') || '30') === '30' && (p.get('algorithm') || 'SHA1').toUpperCase() === 'SHA1'
    if (plain && p.get('secret')) return ['Setup key', p.get('secret')]
  } catch {}
  return ['Setup link', spec]
}

function fieldRow(f) {
  const label = f.label || 'Field'
  switch (f.type) {
    case 'concealed': case 'card_number': case 'ssh_key': return secretRow(label, f.value)
    case 'url': return urlRow(label, f.value)
    case 'otp': return otpRow(label, f.value)
    default: return /^https?:\/\/\S+$/i.test(f.value) ? urlRow(label, f.value) : textRow(label, f.value)
  }
}

function monogram(title) {
  const tile = el('div', { class: 'tile', 'aria-hidden': 'true' }, (Array.from(title.trim())[0] || '?').toUpperCase())
  let h = 0
  for (const ch of title) h = (h * 31 + ch.codePointAt(0)) % 360
  tile.style.setProperty('--h', h)
  return tile
}

function render(it) {
  const title = it.title || 'Untitled'
  const main_ = [
    it.username && textRow('Username', it.username),
    it.password && secretRow('Password', it.password),
    it.totp && otpRow('One-time code', it.totp),
    ...(it.urls || []).filter(Boolean).map((u, i, all) => urlRow(all.length > 1 ? `Website ${i + 1}` : 'Website', u)),
  ].filter(Boolean)
  const group = (heading, rows) => (rows.length ? el('section', { class: 'group' }, heading && el('h2', {}, heading), ...rows) : null)
  const updated = it.updated || it.created
  const h = el('h1', { tabindex: '-1' }, title)
  main.replaceChildren(...[
    el('div', { class: 'title' }, monogram(title), el('div', {}, h, el('div', { class: 'kind' }, kindName(it.kind)))),
    el('p', { class: 'notice' }, 'This link may open only once. Copy what you need now, because it might not work again after you leave this page.'),
    group(null, main_),
    ...(it.sections || []).map((s) => group(s.title, (s.fields || []).filter((f) => f.value).map(fieldRow))),
    it.notes && group(null, [textRow('Notes', it.notes)]),
    it.tags?.length ? el('p', { class: 'meta' }, `Tags: ${it.tags.join(', ')}`) : null,
    updated ? el('p', { class: 'meta' }, `Last changed ${new Date(updated).toLocaleDateString(undefined, { dateStyle: 'long' })}`) : null,
  ].filter(Boolean))
  announce('')
  h.focus()
  if (otpRows.length) setInterval(() => otpRows.forEach((t) => t()), 1000)
}

// Pasting another link into this tab only changes the fragment; start over for it.
window.addEventListener('hashchange', () => location.reload())
start()
