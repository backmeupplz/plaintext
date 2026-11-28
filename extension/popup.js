// The toolbar popup: unlock, the current site's logins first, fill, copy, the
// generator and an item view. Secrets come from the background one item at a
// time, only when the user opens or copies them.
import { ask, copy, el, explain, icon, iconButton, monogram, problemText } from './lib/ui.js'

const main = document.getElementById('main')
const status = document.getElementById('status')
let statusTimer
function say(text, kind = '') {
  status.textContent = text
  status.className = `status ${kind}`
  clearTimeout(statusTimer)
  if (text) statusTimer = setTimeout(() => (status.textContent = ''), 6000)
}

// The page under the toolbar popup, or the tab named in ?tab= when the popup
// is opened as a page of its own (only the extension can open its pages).
const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
const tabId = Number(new URLSearchParams(location.search).get('tab')) || tab?.id
const openSettings = () => chrome.runtime.openOptionsPage().then(() => close())
const header = (...right) =>
  el('header', { class: 'bar' }, el('h1', { class: 'wordmark' }, 'plain', el('span', {}, 'text')), el('div', { class: 'bar-actions' }, ...right))

async function start() {
  let st
  try {
    st = await ask('status')
  } catch (e) {
    return main.replaceChildren(el('p', { class: 'error pad' }, explain(e)))
  }
  if (!st.accounts.length) return welcome()
  if (!st.accounts.some((a) => a.unlocked)) return locked(st.accounts)
  return landing()
}

/** Unlocked: the generator when the page's focused field wants a new password
 *  (unless a submitted login is waiting to be saved), the list otherwise. */
async function landing(problems = []) {
  const [signup, waiting] = await Promise.all([ask('signupField', { tabId }).catch(() => false), ask('pending', { tabId }).catch(() => null)])
  return signup && !waiting && !problems.length ? generator() : home(problems)
}

const hostOf = (server) => new URL(server).host
/** Why an account that was unlocked can't be used now, if it can't. */
const whyLocked = (a) => (a.error ? `${a.username} on ${hostOf(a.server)}: ${explain(a.error)}` : null)

function welcome() {
  main.replaceChildren(
    header(),
    el(
      'section',
      { class: 'center' },
      el('p', {}, 'Your passwords, encrypted on your devices. Your server only ever sees ciphertext.'),
      el('p', { class: 'muted' }, 'Sign in with your server address, Secret Key and password to fill and save logins here.'),
      el('button', { class: 'primary', onclick: openSettings }, icon('plus'), 'Add your account'),
    ),
  )
}

function locked(accounts) {
  const pw = el('input', { type: 'password', id: 'pw', autocomplete: 'current-password', required: true })
  const go = el('button', { class: 'primary', type: 'submit' }, icon('lock'), 'Unlock')
  const err = el('p', { class: 'error', role: 'alert' })
  const form = el(
    'form',
    { class: 'center', onsubmit: (e) => unlock(e, pw, go, err) },
    el('p', {}, accounts.length > 1 ? `Unlock your ${accounts.length} accounts.` : `Unlock ${accounts[0].username} on ${hostOf(accounts[0].server)}.`),
    ...accounts.map(whyLocked).filter(Boolean).map((t) => el('p', { class: 'muted small-text' }, t)),
    el('label', { for: 'pw' }, 'Password'),
    pw,
    err,
    go,
  )
  main.replaceChildren(header(iconButton('settings', 'Settings', openSettings)), form)
  pw.focus()
}

async function unlock(e, pw, go, err) {
  e.preventDefault()
  go.disabled = true
  go.lastChild.textContent = 'Unlocking…'
  err.textContent = ''
  try {
    const results = await ask('unlock', { password: pw.value })
    const failed = results.filter((r) => !r.ok)
    // A password the browser knew but the server refused says more than "didn't match".
    const changed = failed.find((r) => r.error === 'password_changed')
    if (failed.length === results.length) {
      const f = changed ?? failed[0]
      err.textContent = explain({ name: f?.error, message: f?.message })
      return
    }
    const others = failed.length - (changed ? 1 : 0)
    const notes = [changed && explain({ name: changed.error, message: changed.message }), others && `${others} account${others > 1 ? 's use' : ' uses'} another password and stayed locked.`]
    if (failed.length) say(notes.filter(Boolean).join(' '), 'warn')
    const problems = results.flatMap((r) => r.problems ?? [])
    return landing(problems)
  } catch (x) {
    err.textContent = explain(x)
  } finally {
    go.disabled = false
    go.lastChild.textContent = 'Unlock'
    pw.select()
  }
}

// ---------- The list ----------

let query = ''
async function home(problems = []) {
  const search = el('input', { type: 'search', id: 'search', placeholder: 'Search', 'aria-label': 'Search', autocomplete: 'off', value: query })
  const list = el('div', { class: 'list', id: 'list' })
  const note = el('div')
  main.replaceChildren(
    header(
      iconButton('wand-sparkles', 'Generate a password', () => generator()),
      iconButton('refresh-cw', 'Sync now', async () => {
        say('Syncing…')
        try {
          const p = await ask('sync')
          say(p.length ? '' : 'Up to date.')
          showProblems(note, p)
          await render(list)
        } catch (x) {
          say(explain(x), 'error')
        }
      }),
      iconButton('settings', 'Settings', openSettings),
      iconButton('lock', 'Lock', async () => {
        await ask('lock')
        start()
      }),
    ),
    el('div', { class: 'search' }, icon('search'), search),
    note,
    list,
  )
  showProblems(note, problems)
  offerSave(note)
  lockedAccounts(note)
  search.addEventListener('input', () => {
    query = search.value
    render(list)
  })
  search.addEventListener('keydown', (e) => {
    const first = list.querySelector('.row')
    if (e.key === 'ArrowDown' && first) {
      e.preventDefault()
      first.focus()
    }
  })
  await render(list)
  search.focus()
  // A quiet refresh if the last sync is a while ago.
  ask('sync', { ifOlderThan: 5 * 60_000 })
    .then((p) => p && (showProblems(note, p), offerSave(note), render(list)))
    .catch(() => {})
}

/** A login submitted on this tab, waiting to be saved: confirmed here, never in the page. */
async function offerSave(note) {
  const p = await ask('pending', { tabId }).catch(() => null)
  if (!p) return
  const update = p.offer === 'update'
  const banner = el(
    'div',
    { class: 'banner offer', role: 'group', 'aria-label': 'Save login' },
    el(
      'div',
      { class: 'row-text' },
      el('div', {}, update ? `Update the saved password for ${p.username || 'this login'} on ${p.host}?` : `Save the login you just used on ${p.host}?`),
      el('div', { class: 'muted small-text' }, p.username ? `Username: ${p.username}` : 'No username'),
    ),
    el(
      'div',
      { class: 'row-actions' },
      el('button', { class: 'small', type: 'button', onclick: () => decide(false) }, 'Not now'),
      el('button', { class: 'primary small', type: 'button', onclick: () => decide(true) }, update ? 'Update' : 'Save'),
    ),
  )
  async function decide(yes) {
    banner.remove()
    try {
      const r = await ask('savePending', { tabId, save: yes })
      if (r?.queued) say("Saved on this device. It goes to your server at the next sync.", 'warn')
      else if (r?.saved) say('Saved to Plaintext.')
      if (yes) render(document.getElementById('list'))
    } catch (e) {
      say(explain(e), 'error')
    }
  }
  note.querySelector('.offer:not(.leave)')?.remove()
  note.prepend(banner)
}

/** Accounts still locked while others are open, each with its own password. */
async function lockedAccounts(note) {
  const st = await ask('status').catch(() => null)
  for (const old of note.querySelectorAll('.locked-account')) old.remove()
  for (const a of st?.accounts.filter((x) => !x.unlocked) ?? []) {
    const pw = el('input', { type: 'password', autocomplete: 'current-password', required: true, 'aria-label': `Password for ${a.username} on ${hostOf(a.server)}` })
    const err = el('p', { class: 'error small-text', role: 'alert' })
    const go = el('button', { class: 'primary small', type: 'submit' }, 'Unlock')
    const form = el(
      'form',
      {
        class: 'unlock-one',
        hidden: true,
        onsubmit: async (e) => {
          e.preventDefault()
          go.disabled = true
          err.textContent = ''
          try {
            const [r] = await ask('unlock', { password: pw.value, key: a.key })
            if (!r?.ok) return (err.textContent = explain({ name: r?.error, message: r?.message }))
            home(r.problems ?? [])
          } catch (x) {
            err.textContent = explain(x)
          } finally {
            go.disabled = false
          }
        },
      },
      el('div', { class: 'unlock-row' }, pw, go),
      err,
    )
    const banner = el(
      'div',
      { class: 'banner locked-account', role: 'group', 'aria-label': `${a.username} is locked` },
      el(
        'div',
        { class: 'unlock-head' },
        el('div', { class: 'row-text' }, el('div', {}, `${a.username} on ${hostOf(a.server)} is locked`), a.error ? el('div', { class: 'muted small-text' }, explain(a.error)) : null),
        el('button', { class: 'small', type: 'button', onclick: () => ((form.hidden = !form.hidden), form.hidden || pw.focus()) }, icon('lock'), 'Unlock'),
      ),
      form,
    )
    note.append(banner)
  }
}

function showProblems(note, problems) {
  for (const old of note.querySelectorAll('.problem')) old.remove()
  const banners = problems.map((p) => problem(note, p))
  // An open leave confirmation outlives a sync while its vault still offers Leave,
  // standing in for that vault's new banner; it goes once nothing offers it.
  for (const box of note.querySelectorAll('.leave')) {
    box.banner = banners.find((x) => x.leaveKey === box.leaveKey)
    if (!box.banner && !box.busy) box.remove()
  }
  const open = new Set([...note.querySelectorAll('.leave')].map((x) => x.leaveKey))
  note.append(...banners.filter((b) => !open.has(b.leaveKey)))
}

/** One sync problem; one that names a vault you didn't create offers to leave it. */
function problem(note, p) {
  const banner = el('div', { class: 'banner warn problem', role: 'alert' }, icon('triangle-alert'), el('span', { class: 'row-text' }, problemText(p.text)))
  banner.about = p.about && `${p.key} ${p.about}`
  banner.leaveKey = p.vault && `${p.key} ${p.vault}`
  if (p.vault) banner.append(el('button', { class: 'small', type: 'button', onclick: () => confirmLeave(note, banner, p) }, 'Leave…'))
  return banner
}

/** Say what leaving does, as the CLI does, before it happens. */
async function confirmLeave(note, banner, p) {
  let c
  try {
    c = await ask('leaveCheck', { key: p.key, vault: p.vault })
  } catch (e) {
    return say(explain(e), 'error')
  }
  const name = c.name || 'this vault'
  const warnings = [
    // A vault this device can't open has no name here: say which one by its id.
    c.name ? null : `Vault ${p.vault}.`,
    "This takes you and your agents out of the vault. If nobody else uses it, it's deleted with everything in it.",
    c.only_owner && "You're its only owner: the others keep it, but nobody can add people to it or replace its key any more.",
    c.unsent && "Changes to it that haven't reached the server yet are lost.",
  ]
  const key = banner.leaveKey
  // Already open for this vault (a second click while the check was out).
  const already = [...note.querySelectorAll('.leave')].find((x) => x.leaveKey === key)
  if (already) return already.querySelector('button').focus()
  const cancel = el('button', { class: 'small', type: 'button', onclick: () => back() }, 'Cancel')
  const box = el(
    'div',
    { class: 'banner offer leave', role: 'group', 'aria-label': `Leave ${name}` },
    el('div', { class: 'row-text' }, el('div', {}, `Leave ${name}?`), el('div', { class: 'muted small-text' }, warnings.filter(Boolean).join(' '))),
    el('div', { class: 'row-actions' }, cancel, el('button', { class: 'primary small', type: 'button', onclick: () => leave() }, 'Leave vault')),
  )
  box.leaveKey = key
  // A sync during the check may have rebuilt the banners: stand in for this vault's current one.
  box.banner = banner.isConnected ? banner : [...note.querySelectorAll('.problem')].find((x) => x.leaveKey === key)
  if (box.banner) box.banner.replaceWith(box)
  else note.append(box)
  cancel.focus()
  /** Back to the vault's banner, if a problem still offers it. */
  function back() {
    const b = box.banner
    if (b) {
      box.replaceWith(b)
      b.querySelector('button')?.focus()
    } else box.remove()
  }
  async function leave() {
    box.busy = true
    for (const b of box.querySelectorAll('button')) b.disabled = true
    try {
      await ask('leave', { key: p.key, vault: p.vault })
      box.remove()
      // Nothing the last sync said about the vault applies any more.
      for (const b of note.querySelectorAll('.problem')) if (b.about === `${p.key} ${p.vault}`) b.remove()
      say(`Left ${c.name || 'the vault'}.`)
      render(document.getElementById('list'))
    } catch (e) {
      box.busy = false
      back()
      say(explain(e), 'error')
    }
  }
}

let renderSeq = 0
async function render(list) {
  const seq = ++renderSeq
  let data
  try {
    data = await ask('list', { tabId, query })
  } catch (e) {
    if (e.name === 'locked' || e.name === 'signed_out') return start()
    return list.replaceChildren(el('p', { class: 'error pad' }, explain(e)))
  }
  if (seq !== renderSeq) return
  const here = data.rows.filter((r) => r.here)
  const rest = data.rows.filter((r) => !r.here)
  const out = []
  if (here.length) out.push(el('h2', {}, `On ${data.page}`), ...here.map((r) => row(r, data)))
  if (rest.length) out.push(el('h2', {}, query ? 'Results' : 'All items'), ...rest.map((r) => row(r, data)))
  if (!data.rows.length) {
    out.push(
      el(
        'p',
        { class: 'empty' },
        query ? `Nothing matches “${query}”.` : 'No items yet. Sign in somewhere and Plaintext offers to save the login, or add items in the Plaintext app.',
      ),
    )
  }
  list.replaceChildren(...out)
}

function row(r, data) {
  const secondary = [r.username, data.several ? r.account : null].filter(Boolean).join(' · ') || r.vault_name
  const actions = el('div', { class: 'row-actions' })
  if (r.here && r.has_password) actions.append(el('button', { class: 'primary small', type: 'button', onclick: (e) => (e.stopPropagation(), fillItem(r)) }, 'Fill'))
  if (r.username) actions.append(iconButton('user', `Copy username for ${r.title}`, (e) => (e.stopPropagation(), copy(r.username, say))))
  if (r.has_password) actions.append(iconButton('copy', `Copy password for ${r.title}`, (e) => (e.stopPropagation(), copyField(r, 'password'))))
  const div = el(
    'div',
    { class: 'row', tabindex: '0', role: 'button', 'aria-label': `${r.title}, ${secondary}`, onclick: () => itemView(r) },
    monogram(r.title),
    el('div', { class: 'row-text' }, el('div', { class: 'title' }, r.title || 'Untitled'), el('div', { class: 'muted small-text' }, secondary)),
    actions,
  )
  div.addEventListener('keydown', (e) => {
    if (e.target !== div) return
    if (e.key === 'Enter') r.here && r.has_password ? fillItem(r) : itemView(r)
    if (e.key === 'ArrowDown') div.nextElementSibling?.matches('.row') ? div.nextElementSibling.focus() : null
    if (e.key === 'ArrowUp') (div.previousElementSibling?.matches('.row') ? div.previousElementSibling : document.getElementById('search'))?.focus()
  })
  return div
}

async function fillItem(r) {
  try {
    await ask('fill', { tabId, key: r.account, vault: r.vault, id: r.id })
    close()
  } catch (e) {
    say(explain(e), 'error')
  }
}

async function copyField(r, field) {
  try {
    const it = await ask('item', { key: r.account, vault: r.vault, id: r.id })
    await copy(it[field] ?? '', say)
  } catch (e) {
    say(explain(e), 'error')
  }
}

// ---------- One item ----------

async function itemView(r) {
  let it
  try {
    it = await ask('item', { key: r.account, vault: r.vault, id: r.id })
  } catch (e) {
    return say(explain(e), 'error')
  }
  const fields = []
  if (it.username) fields.push(field('Username', it.username))
  if (it.password) fields.push(field('Password', it.password, { secret: true }))
  if (it.totp) fields.push(await otpField(it.totp))
  for (const u of it.urls ?? []) fields.push(urlField(u))
  for (const s of it.sections ?? []) {
    for (const f of s.fields ?? []) {
      if (!f.value) continue
      fields.push(field(f.label || s.title || 'Field', f.value, { secret: ['concealed', 'password', 'pin', 'card_number'].includes(f.type) }))
    }
  }
  if (it.urls?.length && it.password && r.writable) fields.push(exactHostField(r, it))
  if (it.notes) fields.push(el('div', { class: 'field' }, el('div', { class: 'label' }, 'Notes'), el('div', { class: 'notes' }, it.notes)))
  main.replaceChildren(
    el(
      'header',
      { class: 'bar' },
      iconButton('arrow-left', 'Back', () => home()),
      el('div', { class: 'bar-actions' }, r.here && r.has_password ? el('button', { class: 'primary small', onclick: () => fillItem(r) }, 'Fill') : null),
    ),
    el('div', { class: 'item-head' }, monogram(it.title), el('div', {}, el('h2', { class: 'item-title' }, it.title || 'Untitled'), el('div', { class: 'muted small-text' }, `${r.vault_name} · ${it.kind || 'item'}`))),
    el('div', { class: 'fields' }, ...fields),
  )
  main.querySelector('button')?.focus()
}

function field(label, value, { secret = false } = {}) {
  const shown = el('div', { class: `value${secret ? ' mono' : ''}` }, secret ? '••••••••••••' : value)
  const actions = el('div', { class: 'row-actions' })
  if (secret) {
    let open = false
    const eye = iconButton('eye', `Show ${label.toLowerCase()}`, () => {
      open = !open
      shown.textContent = open ? value : '••••••••••••'
      eye.replaceChildren(icon(open ? 'eye-off' : 'eye'))
      eye.setAttribute('aria-label', `${open ? 'Hide' : 'Show'} ${label.toLowerCase()}`)
    })
    actions.append(eye)
  }
  actions.append(iconButton('copy', `Copy ${label.toLowerCase()}`, () => copy(value, say)))
  return el('div', { class: 'field' }, el('div', { class: 'field-text' }, el('div', { class: 'label' }, label), shown), actions)
}

async function otpField(spec) {
  const code = el('div', { class: 'value mono' })
  const left = el('span', { class: 'muted small-text' })
  let current = ''
  const tick = async () => {
    if (!code.isConnected && current) return clearInterval(timer)
    const t = await ask('totp', { spec }).catch(() => null)
    if (!t) return (code.textContent = 'Unreadable one-time code')
    current = t[0]
    code.textContent = `${current.slice(0, 3)} ${current.slice(3)}`
    left.textContent = ` ${t[1]} s`
  }
  const timer = setInterval(tick, 1000)
  await tick()
  return el(
    'div',
    { class: 'field' },
    el('div', { class: 'field-text' }, el('div', { class: 'label' }, 'One-time code', left), code),
    el('div', { class: 'row-actions' }, iconButton('copy', 'Copy one-time code', () => copy(current, say))),
  )
}

function exactHostField(r, it) {
  let host = ''
  try {
    host = new URL(/^https?:\/\//i.test(it.urls[0]) ? it.urls[0] : `https://${it.urls[0]}`).host
  } catch {}
  const box = el('input', { type: 'checkbox', id: 'exact', checked: it.exact_host })
  box.addEventListener('change', async () => {
    try {
      const done = await ask('setExactHost', { key: r.account, vault: r.vault, id: r.id, exact: box.checked })
      const now = box.checked ? `Fills only on ${host} now.` : 'Fills anywhere on this site now.'
      say(done?.queued ? `${now} Saved on this device; it goes to your server at the next sync.` : now, done?.queued ? 'warn' : '')
    } catch (e) {
      // Only these left the item as it was; any other error kept the change on this device.
      if (['refused', 'not_found', 'locked'].includes(e.name)) box.checked = !box.checked
      say(explain(e), 'error')
    }
  })
  return el('div', { class: 'field' }, el('label', { class: 'check', for: 'exact' }, box, `Fill only on ${host || 'this exact host'}, not the rest of its site`))
}

function urlField(u) {
  const href = /^https?:\/\//i.test(u) ? u : `https://${u}`
  const safe = /^https?:\/\//i.test(href)
  return el(
    'div',
    { class: 'field' },
    el('div', { class: 'field-text' }, el('div', { class: 'label' }, 'Website'), el('div', { class: 'value' }, u)),
    el('div', { class: 'row-actions' }, safe ? iconButton('external-link', 'Open website', () => chrome.tabs.create({ url: href })) : null, iconButton('copy', 'Copy website', () => copy(u, say))),
  )
}

// ---------- Generator ----------

const recipe = { type: 'random', length: 20, digits: true, symbols: true }
async function generator() {
  const out = el('div', { class: 'generated mono', 'aria-live': 'polite' })
  const meter = el('div', { class: 'meter' }, el('span'))
  const strengthText = el('span', { class: 'muted small-text' })
  let password = ''
  const regen = async () => {
    const g = await ask('generate', { recipe })
    password = g.password
    out.textContent = password
    const pct = Math.min(100, (g.bits / 128) * 100)
    meter.firstChild.style.width = `${pct}%`
    strengthText.textContent = `About ${Math.round(g.bits)} bits`
  }
  const len = el('input', { type: 'range', min: 8, max: 64, value: recipe.length, id: 'len', 'aria-label': 'Length' })
  const lenText = el('span', {}, String(recipe.length))
  len.addEventListener('input', () => {
    recipe.length = Number(len.value)
    lenText.textContent = len.value
    regen()
  })
  const toggle = (key, label) => {
    const c = el('input', { type: 'checkbox', id: key, checked: recipe[key] })
    c.addEventListener('change', () => {
      recipe[key] = c.checked
      regen()
    })
    return el('label', { class: 'check', for: key }, c, label)
  }
  main.replaceChildren(
    el('header', { class: 'bar' }, iconButton('arrow-left', 'Back', () => home()), el('h2', { class: 'bar-title' }, 'New password')),
    el('div', { class: 'pad' }, out, meter, strengthText),
    el('div', { class: 'pad' }, el('label', { for: 'len' }, 'Length ', lenText), len, el('div', { class: 'checks' }, toggle('digits', 'Digits'), toggle('symbols', 'Symbols'))),
    el(
      'div',
      { class: 'pad buttons' },
      iconButton('refresh-cw', 'Another one', regen, 'icon-btn bordered'),
      el('button', { type: 'button', onclick: () => copy(password, say) }, icon('copy'), 'Copy'),
      el(
        'button',
        {
          class: 'primary',
          type: 'button',
          onclick: async () => {
            try {
              await ask('fillPassword', { tabId, password })
              close()
            } catch (e) {
              say(explain(e), 'error')
            }
          },
        },
        'Use on this page',
      ),
    ),
    el('p', { class: 'pad muted small-text' }, 'After you sign up, Plaintext offers to save the new login.'),
  )
  await regen()
}

start()
