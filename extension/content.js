// Runs in web pages (top frames only). It never sees a saved password until
// the user picks one in Plaintext's own popup or presses the shortcut; it only
// fills and tells the background about a submitted login, which the user then
// saves from the popup. Nothing it shows depends on what's saved. Its little UI
// lives in a closed shadow root and acts only on real clicks (isTrusted).
;(() => {
  if (window.top !== window || globalThis.__plaintext) return
  globalThis.__plaintext = true

  const ask = (msg) => chrome.runtime.sendMessage(msg).then((r) => r?.ok ?? null, () => null)

  // ---------- Finding fields ----------

  function shown(el) {
    const r = el.getBoundingClientRect()
    return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden'
  }
  const usable = (el) => !el.disabled && !el.readOnly && shown(el)
  const passwords = (scope = document) => [...scope.querySelectorAll('input[type=password]')].filter(usable)
  const TEXTY = ['text', 'email', 'tel', '']

  /** The username field that goes with a password field (or the page's only one). */
  function usernameFor(pw) {
    const scope = pw?.form ?? document
    const inputs = [...scope.querySelectorAll('input')].filter((i) => usable(i) && (i === pw || TEXTY.includes(i.type)))
    const before = pw ? inputs.slice(0, inputs.indexOf(pw)).reverse() : inputs
    const texty = before.filter((i) => i !== pw)
    const named = texty.find((i) => /username|email/.test(i.autocomplete)) ?? texty.find((i) => /user|mail|login/i.test(`${i.name} ${i.id}`))
    // Without a password field (a username-first page), only a field that says what it is.
    return named ?? (pw ? (texty[0] ?? null) : null)
  }

  function setValue(el, value) {
    el.focus()
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, value)
    el.dispatchEvent(new Event('input', { bubbles: true }))
    el.dispatchEvent(new Event('change', { bubbles: true }))
  }

  // Where the form can send what's filled: its action and every submit
  // button's formaction, as the browser resolves them (<base> included), read
  // through the prototypes so fields named "action" can't stand in for them.
  const getter = (proto, name) => Object.getOwnPropertyDescriptor(proto, name).get
  const formActionOf = getter(HTMLFormElement.prototype, 'action')
  const formElements = getter(HTMLFormElement.prototype, 'elements')
  const buttonAction = getter(HTMLButtonElement.prototype, 'formAction')
  const inputAction = getter(HTMLInputElement.prototype, 'formAction')
  function destinations(el) {
    const form = el?.form
    if (!form) return []
    const out = new Set([formActionOf.call(form)])
    // Every control of the form, including buttons outside it that join with
    // form="…" (image inputs aren't in `elements`, so they're looked up too).
    for (const b of [...formElements.call(form), ...document.querySelectorAll('input[type=image]')]) {
      if (b.form !== form) continue
      if (b instanceof HTMLButtonElement || (b instanceof HTMLInputElement && /^(submit|image)$/.test(b.type))) {
        out.add((b instanceof HTMLButtonElement ? buttonAction : inputAction).call(b))
      }
    }
    return [...out]
  }

  /** Fill the login form. The background has checked the item belongs to this page. */
  function fill({ username, password, origin, allowActions = [] }) {
    if (location.origin !== origin) return { result: 'moved' }
    const pw = passwords().find((p) => !/new-password/.test(p.autocomplete)) ?? null
    const user = usernameFor(pw)
    const target = pw ?? user
    if (!target) return { result: 'no-form' }
    // Anything but this origin (another site, mailto:) needs the background's say-so.
    // javascript: sends nothing anywhere; the page's own script handles the form.
    const elsewhere = destinations(target).filter((u) => !/^javascript:/i.test(u) && (!/^https?:/i.test(u) || new URL(u).origin !== location.origin))
    if (elsewhere.some((u) => !allowActions.includes(u))) return { needActions: elsewhere }
    if (user && username) setValue(user, username)
    if (pw && password) setValue(pw, password)
    return { result: 'filled' }
  }

  /** New-password fields: marked as such, or a pair (new + confirm). */
  function newPasswordFields() {
    const all = passwords()
    const marked = all.filter((p) => p.autocomplete === 'new-password')
    if (marked.length) return marked
    for (const p of all) {
      const inForm = passwords(p.form ?? document)
      // Never a change-password form's current password.
      if (inForm.length === 2 && !inForm.some((f) => /current-password/.test(f.autocomplete))) return inForm
    }
    return all.length === 1 && !/current-password/.test(all[0].autocomplete) ? all : []
  }

  /** A field that's clearly for a new password: marked so, or one of a form's
   *  new + confirm pair (not a change-password form's current one). */
  function signupField(f) {
    if (!(f instanceof HTMLInputElement) || f.type !== 'password' || !usable(f)) return false
    if (/new-password/.test(f.autocomplete)) return true
    const inForm = f.form ? passwords(f.form) : []
    return inForm.length === 2 && !inForm.some((p) => /current-password/.test(p.autocomplete))
  }

  chrome.runtime.onMessage.addListener((msg, sender, reply) => {
    if (sender.id !== chrome.runtime.id || sender.tab) return false
    if (msg.action === 'fill') reply(fill(msg))
    if (msg.action === 'signupField') reply(signupField(document.activeElement))
    if (msg.action === 'fillNew') {
      const fields = newPasswordFields()
      for (const f of fields) setValue(f, msg.password)
      reply({ result: fields.length ? 'filled' : 'no-form' })
    }
    return false
  })

  // ---------- Noticing a submitted login ----------

  const SUBMITS = /log\s?in|sign\s?(in|up|on)|continue|next|submit|register|create|join|save/i
  let lastSent = ''
  function submitted(scope) {
    const filled = passwords(scope ?? document).filter((p) => p.value)
    if (!filled.length) return
    // Sign-up and change forms: the new password (the marked one, or the last).
    const pw = filled.find((p) => p.autocomplete === 'new-password') ?? filled[filled.length - 1]
    const username = usernameFor(pw)?.value ?? ''
    const key = `${username}\n${pw.value}`
    if (key === lastSent) return
    lastSent = key
    ask({ action: 'submitted', username, password: pw.value })
  }
  document.addEventListener('submit', (e) => e.isTrusted && submitted(e.target), true)
  document.addEventListener(
    'click',
    (e) => {
      const b = e.isTrusted && e.target.closest?.('button, input[type=submit], input[type=button], [role=button]')
      if (!b) return
      // In a form, its submit button; elsewhere (script-driven sign-ins) one that says so.
      const form = b.form ?? b.closest('form')
      if (form ? b.type === 'submit' : SUBMITS.test(b.textContent || b.value || '')) submitted(form ?? document)
    },
    true,
  )
  document.addEventListener('keydown', (e) => e.isTrusted && e.key === 'Enter' && e.target?.type === 'password' && submitted(e.target.form ?? document), true)

  // ---------- Plaintext's own bits of UI ----------

  const host = document.createElement('plaintext-ui')
  for (const [k, v] of Object.entries({ all: 'initial', position: 'fixed', 'z-index': '2147483647', top: '0', left: '0', width: '0', height: '0', opacity: '1', visibility: 'visible', display: 'block' })) {
    host.style.setProperty(k, v, 'important')
  }
  const root = host.attachShadow({ mode: 'closed' })
  const style = document.createElement('style')
  style.textContent = `
    :host { color-scheme: light dark; }
    .toast { position: fixed; top: 16px; right: 16px; width: 320px; box-sizing: border-box; padding: 14px 16px; border-radius: 12px;
      font: 14px/1.4 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; background: #fbfbf8; color: #1b1b19;
      border: 1px solid #e4e3dc; box-shadow: 0 8px 30px rgba(0,0,0,.18); }
    .toast p { margin: 0; }
    .row { display: flex; justify-content: flex-end; margin-top: 12px; }
    button { font: inherit; border-radius: 8px; padding: 6px 14px; min-height: 32px; cursor: pointer; border: 1px solid #e4e3dc; background: #f3f2ec; color: #1b1b19; }
    .mark { position: fixed; width: 22px; height: 22px; padding: 0; min-height: 0; border: 0; border-radius: 6px; background: #1f7a4d; color: #fff; display: grid; place-items: center; }
    .mark svg { width: 14px; height: 14px; }
    @media (prefers-color-scheme: dark) {
      .toast { background: #191917; color: #ecebe5; border-color: #282825; }
      button { background: #1d1d1b; color: #ecebe5; border-color: #282825; } .mark { background: #4cc38a; color: #0d1f16; }
    }`
  root.append(style)
  const attach = () => host.isConnected || document.documentElement.append(host)

  let toastEl = null
  function closeToast() {
    toastEl?.remove()
    toastEl = null
  }
  /** A note with a Close button (only for the mark's fallback below). */
  function note(text) {
    closeToast()
    attach()
    toastEl = document.createElement('div')
    toastEl.className = 'toast'
    toastEl.setAttribute('role', 'status')
    const p = document.createElement('p')
    p.textContent = text
    const close = document.createElement('button')
    close.textContent = 'Close'
    close.addEventListener('click', (e) => e.isTrusted && closeToast())
    const row = document.createElement('div')
    row.className = 'row'
    row.append(close)
    toastEl.append(p, row)
    root.append(toastEl)
  }

  // Lets the background show a waiting save on the toolbar button again after
  // the sign-in navigated (browsers clear the badge then).
  ask({ action: 'loaded' })

  // ---------- The mark in login fields ----------

  const NS = 'http://www.w3.org/2000/svg'
  const mark = document.createElement('button')
  mark.className = 'mark'
  mark.setAttribute('aria-label', 'Fill with Plaintext')
  mark.title = 'Fill with Plaintext'
  const svg = document.createElementNS(NS, 'svg')
  svg.setAttribute('viewBox', '0 0 32 32')
  for (const [tag, attrs] of [['circle', { cx: 16, cy: 13, r: 4.5 }], ['path', { d: 'M13.6 15.5h4.8l1.4 9h-7.6z' }]]) {
    const e = document.createElementNS(NS, tag)
    for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v)
    e.setAttribute('fill', 'currentColor')
    svg.append(e)
  }
  mark.append(svg)
  let field = null
  // Keep the field focused while the mark is clicked.
  mark.addEventListener('mousedown', (e) => e.preventDefault())
  mark.addEventListener('click', async (e) => {
    if (!e.isTrusted) return
    // Filling happens in Plaintext's own popup, which a page can't cover or restyle.
    if (!(await ask({ action: 'openPopup' }))) {
      const keys = navigator.platform.startsWith('Mac') ? '⌘⇧L' : 'Ctrl+Shift+L'
      note(`Click Plaintext in the toolbar to choose a login, or press ${keys} to fill the best one.`)
    }
  })
  function place() {
    if (!field?.isConnected) return hideMark()
    const r = field.getBoundingClientRect()
    mark.style.top = `${r.top + (r.height - 22) / 2}px`
    mark.style.left = `${r.right - 28}px`
  }
  function hideMark() {
    mark.remove()
    field = null
  }
  document.addEventListener(
    'focusin',
    (e) => {
      const t = e.target
      if (!(t instanceof HTMLInputElement) || !usable(t)) return
      const isLogin = t.type === 'password' || (TEXTY.includes(t.type) && passwords(t.form ?? document).length && usernameFor(passwords(t.form ?? document)[0]) === t)
      if (!isLogin || t.getBoundingClientRect().width < 80) return
      field = t
      attach()
      root.append(mark)
      place()
    },
    true,
  )
  document.addEventListener('focusout', () => setTimeout(() => document.activeElement !== field && hideMark(), 150), true)
  addEventListener('scroll', place, { passive: true, capture: true })
  addEventListener('resize', place, { passive: true })
})()
