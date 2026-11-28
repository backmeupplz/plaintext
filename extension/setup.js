// Settings: add and remove accounts, auto-lock, the fill shortcut.
import { ask, el, explain, keyStep, problemText } from './lib/ui.js'

const $ = (id) => document.getElementById(id)
const FIREFOX = chrome.runtime.getURL('').startsWith('moz-extension:')

async function refresh() {
  const st = await ask('status')
  $('lock').value = String(st.lockMinutes)
  $('accounts').replaceChildren(
    ...(st.accounts.length
      ? st.accounts.map((a) =>
          el(
            'li',
            {},
            el('div', { class: 'who' }, el('div', {}, a.username), el('div', { class: 'muted' }, `${a.server}${a.unlocked ? '' : ' · locked'}`)),
            el('button', { type: 'button', onclick: () => remove(a) }, 'Sign out'),
          ),
        )
      : [el('li', { class: 'muted' }, 'No accounts yet.')]),
  )
}

async function remove(a) {
  if (!confirm(`Sign out of ${a.username} on ${a.server}? You'll need its Secret Key to add it again.`)) return
  await ask('remove', { key: a.key })
  refresh()
}

$('add').addEventListener('submit', (e) => {
  e.preventDefault()
  const msg = $('add-msg')
  const btn = $('add-btn')
  let url
  try {
    url = new URL($('server').value.trim())
    if (!/^https?:$/.test(url.protocol)) throw new Error()
  } catch {
    msg.className = 'error'
    msg.textContent = 'Enter the server address, starting with https://.'
    return
  }
  btn.disabled = true
  msg.className = 'muted'
  msg.textContent = 'Signing in… this takes a few seconds.'
  ask('add', { server: url.href, secretKey: $('sk').value, password: $('pw').value })
    .then(function signedIn(r) {
      msg.className = ''
      // The account needs its security key: approve in a new tab, then continue here.
      if (r.error === 'key_needed') {
        msg.textContent = ''
        return $('key-step').replaceChildren(keyStep(r, (done) => ($('key-step').replaceChildren(), signedIn(done))))
      }
      msg.textContent = `Signed in as ${r.username}.${r.problems.length ? ` ${r.problems.map((p) => problemText(p.text)).join(' ')}` : ''}`
      $('add').reset()
      refresh()
    })
    .catch((x) => {
      msg.className = 'error'
      msg.textContent = explain(x)
    })
    .finally(() => (btn.disabled = false))
})

$('lock').addEventListener('change', () => ask('settings', { lockMinutes: $('lock').value }))

chrome.commands.getAll().then((cmds) => {
  const keys = cmds.find((c) => c.name === 'fill')?.shortcut
  const where = FIREFOX ? 'about:addons (Manage Extension Shortcuts)' : 'chrome://extensions/shortcuts'
  $('shortcut').textContent = keys
    ? `Press ${keys} on a login page to fill the best matching login. You can change the shortcut in ${where}.`
    : `Set a shortcut to fill the best matching login in ${where}.`
})

refresh()
