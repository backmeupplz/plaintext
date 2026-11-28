// The extension's background: it holds the unlocked accounts and is the only
// place that talks to Plaintext's core (Rust, as WebAssembly). Pages ask it
// things by message; it checks who is asking before answering.
//
// Storage:
//   local    accounts [{key, server, username, sealed, trust}]  (Secret Key sealed under the password;
//            trust: the token that spares this browser the account's security key, if it needs one)
//            local:<key>  this device's vault and keyring copies, sealed with the Account Key
//            settings {lockMinutes}
//   session  session:<key>  token + Account Key while unlocked (memory only, gone when the browser closes)
//            lockAt, lastSync, pending:<tabId> (a submitted login waiting for the user to save it)
//            signin:<key> a sign-in waiting for the account's security key (holds the Account Unlock Key)
import init, { Account, PendingSignIn, generate, insecureUrl, strength, totp } from './pkg/plaintext_wasm.js'
import { send } from './lib/net.js'

const ready = init({ module_or_path: chrome.runtime.getURL('pkg/plaintext_wasm_bg.wasm') })
const FIREFOX = chrome.runtime.getURL('').startsWith('moz-extension:')
const DEVICE = `${FIREFOX ? 'Firefox' : 'Chrome'} extension`
const CLEAR_AFTER_S = 90
const PENDING_FOR_MS = 3 * 60_000
/** The server forgets a sign-in waiting for its security key after 5 minutes. */
const SIGNIN_FOR_MS = 5 * 60_000

chrome.storage.session.setAccessLevel?.({ accessLevel: 'TRUSTED_CONTEXTS' })

const open = new Map() // key -> Account (wasm)
let chain = Promise.resolve()
/** One core call at a time: a Rust session can't serve two at once. */
function serial(fn) {
  const run = chain.then(fn)
  chain = run.catch(() => {})
  return run
}

const local = async (k) => (await chrome.storage.local.get(k))[k]
const session = async (k) => (await chrome.storage.session.get(k))[k]
const accounts = async () => (await local('accounts')) ?? []
const settings = async () => ({ lockMinutes: 10, ...(await local('settings')) })

function fail(name, message) {
  const e = new Error(message)
  e.name = name
  return e
}

async function save(key, acct) {
  await chrome.storage.local.set({ [`local:${key}`]: acct.localState() })
}

async function remember(a, acct) {
  open.set(a.key, acct)
  await chrome.storage.session.set({ [`session:${a.key}`]: acct.sessionState() })
}

/** Sync, keep this device's copies, and return what the user should know:
 *  `{ text, key, vault, about }`, where `vault` is one the problem offers to leave
 *  and `about` the vault it's about. */
async function sync(a, acct) {
  let problems
  try {
    // The client's text starts lower case ("vault Team wasn't updated…"); other
    // problems (one starting with a username, say) are shown as they are.
    problems = JSON.parse(await acct.sync()).map((p) => ({ text: p.text.charAt(0).toUpperCase() + p.text.slice(1), key: a.key, vault: p.leave, about: p.vault }))
  } catch (e) {
    // The server ended the session (expired, or signed out elsewhere): unlock again.
    if (e.name === 'signed_out') await forget(a.key)
    throw e
  }
  await save(a.key, acct)
  await chrome.storage.session.set({ lastSync: Date.now() })
  return problems
}

/** End an account's session on the server too, so a copied token stops working. */
async function signOut(a) {
  const state = await session(`session:${a.key}`)
  if (state) send('POST', `${a.server}/v1/logout`, JSON.parse(state).token).catch(() => {})
  await forget(a.key)
}

/** Drop an account's unlocked session here (its local copies stay). */
async function forget(key) {
  open.get(key)?.free()
  open.delete(key)
  await chrome.storage.session.remove(`session:${key}`)
}

/** An unlocked account, picked up again if the browser suspended us: from
 *  this device's copies with no network, or from the server if there are none. */
async function account(a) {
  if (open.has(a.key)) return open.get(a.key)
  const state = await session(`session:${a.key}`)
  if (!state) return null
  await ready
  const copies = await local(`local:${a.key}`)
  let acct
  if (copies) {
    acct = Account.restore(send, a.server, state, copies)
  } else {
    try {
      acct = await Account.resume(send, a.server, state)
    } catch (e) {
      if (e.name === 'signed_out') await forget(a.key)
      throw e
    }
  }
  open.set(a.key, acct)
  return acct
}

/** Every unlocked account; one that can't be picked up doesn't hide the others. */
async function unlocked() {
  const out = []
  for (const a of await accounts()) {
    const acct = await account(a).catch(() => null)
    if (acct) out.push([a, acct])
  }
  return out
}

async function touch() {
  const { lockMinutes } = await settings()
  await chrome.storage.session.set({ lockAt: Date.now() + lockMinutes * 60_000 })
  chrome.alarms.create('autolock', { periodInMinutes: 1 })
}

async function lock() {
  for (const acct of open.values()) acct.free()
  open.clear()
  const all = await chrome.storage.session.get(null)
  await chrome.storage.session.clear()
  chrome.alarms.clear('autolock')
  // The save offers went with storage.session; so do their badges.
  for (const k of Object.keys(all)) if (k.startsWith('pending:')) await badge(Number(k.slice(8)), false)
  // End the sessions on the server too, so a copied token stops working.
  for (const a of await accounts()) {
    const state = all[`session:${a.key}`]
    if (state) send('POST', `${a.server}/v1/logout`, JSON.parse(state).token).catch(() => {})
  }
}

async function lockIfIdle() {
  const at = await session('lockAt')
  if (at && Date.now() > at) await lock()
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'autolock') serial(lockIfIdle)
  if (alarm.name === 'signin-expire') serial(awaitingKey)
  if (alarm.name === 'clear-clipboard') clearClipboard()
})

// ---------- Clipboard ----------

// Clears unconditionally: checking that it still holds what we copied would
// need permission to read the clipboard. Chrome's background has no page, so
// it borrows an offscreen document; Firefox's background is a page.
async function clearClipboard() {
  if (globalThis.document) return wipe()
  try {
    await chrome.offscreen.createDocument({ url: 'offscreen.html', reasons: ['CLIPBOARD'], justification: 'Clear a copied password after 90 seconds' })
  } catch {
    // Already open.
  }
  await chrome.runtime.sendMessage({ action: 'wipe-clipboard' })
  await chrome.offscreen.closeDocument().catch(() => {})
}

function wipe() {
  const onCopy = (e) => {
    e.clipboardData.setData('text/plain', '')
    e.preventDefault()
  }
  document.addEventListener('copy', onCopy)
  document.execCommand('copy')
  document.removeEventListener('copy', onCopy)
}

// ---------- Saving a submitted login ----------

// The offer shows as a badge on the toolbar button and is confirmed in the
// popup: nothing in the page, so a page can't learn what's saved from it or
// trick a click on it.
async function badge(tabId, on) {
  await chrome.action.setBadgeBackgroundColor({ color: '#1f7a4d', tabId }).catch(() => {})
  await chrome.action.setBadgeText({ text: on ? '1' : '', tabId }).catch(() => {})
}

async function pending(tabId) {
  const p = await session(`pending:${tabId}`)
  if (p && Date.now() - p.at <= PENDING_FOR_MS) return p
  if (p) await chrome.storage.session.remove(`pending:${tabId}`)
  return null
}

async function savePending(tabId, yes) {
  const p = await pending(tabId)
  await chrome.storage.session.remove(`pending:${tabId}`)
  await badge(tabId, false)
  if (!yes || !p) return null
  const [a, acct] = (await unlocked()).find(([x]) => x.key === p.key) ?? []
  if (!acct) throw fail('locked', 'Unlock Plaintext first, then sign in on the page again to save the login.')
  try {
    await acct.saveLogin(p.page, p.username, p.password)
  } catch (e) {
    // Nothing was made (no vault to save into, say).
    if (e.name === 'refused' || e.name === 'not_found') throw e
    // Made here but not sent: kept on this device and sent at the next sync.
    await save(a.key, acct)
    if (e.name === 'network') return { queued: true }
    if (e.name === 'signed_out') {
      await forget(a.key)
      throw fail(e.name, 'Your session ended. The login is kept on this device and sent after you unlock Plaintext again.')
    }
    throw fail(e.name, `${e.message}. The login is kept on this device and Plaintext tries again at the next sync.`)
  }
  await save(a.key, acct)
  return { saved: true }
}

// ---------- Pages ----------

async function tabPage(tabId) {
  const tab = await chrome.tabs.get(tabId)
  return /^https?:/.test(tab.url ?? '') ? tab.url : null
}

function hostOf(url) {
  try {
    return new URL(url).host
  } catch {
    return null
  }
}

/** Fill through the content script in the tab's top frame (never an iframe). */
async function fillTab(tabId, request) {
  const ask = () => chrome.tabs.sendMessage(tabId, request, { frameId: 0 })
  try {
    return await ask()
  } catch {
    // Opened before the extension was installed: no content script yet.
    await chrome.scripting.executeScript({ target: { tabId, frameIds: [0] }, files: ['content.js'] })
    return ask()
  }
}

async function fill(tabId, key, vault, id) {
  const page = await tabPage(tabId)
  if (!page) throw fail('refused', "Plaintext fills only web pages (http and https).")
  const [, acct] = (await unlocked()).find(([a]) => a.key === key) ?? []
  if (!acct) throw fail('locked', 'Unlock Plaintext first.')
  const creds = JSON.parse(acct.fill(vault, id, page))
  const origin = new URL(page).origin
  let r = await fillTab(tabId, { action: 'fill', ...creds, origin })
  // The form posts somewhere else: fill only if the login is saved for that site too.
  if (r?.needActions) {
    for (const action of r.needActions) {
      if (!/^https?:\/\//i.test(action)) throw fail('refused', "This form sends what you type somewhere other than a web page, so Plaintext won't fill it.")
      acct.fill(vault, id, action)
    }
    r = await fillTab(tabId, { action: 'fill', ...creds, origin, allowActions: r.needActions })
  }
  if (r?.result === 'moved') throw fail('refused', 'The page changed before Plaintext could fill it. Try again.')
  if (r?.result !== 'filled') throw fail('no_form', "Plaintext couldn't find a login form on this page.")
  await touch()
  return true
}

/** The page's logins first; every unlocked account's items. */
async function list(tabId, query) {
  const page = tabId == null ? null : await tabPage(tabId).catch(() => null)
  const rows = []
  for (const [a, acct] of await unlocked()) {
    for (const r of JSON.parse(acct.list(page, query))) rows.push({ ...r, account: a.key })
  }
  rows.sort((x, y) => (y.here ? 1 : 0) - (x.here ? 1 : 0))
  return { page: page && hostOf(page), rows, several: (await accounts()).length > 1 }
}

// ---------- Messages from the extension's own pages ----------

async function fromPage(msg) {
  await lockIfIdle()
  switch (msg.action) {
    case 'status': {
      // Unlocked means usable: an account whose session can't be picked up
      // again shows as locked, with why, so it can be unlocked afresh.
      const list = []
      for (const a of await accounts()) {
        const row = { key: a.key, server: a.server, username: a.username, unlocked: false }
        try {
          row.unlocked = Boolean(await account(a))
        } catch (e) {
          row.error = { name: e.name, message: e.message }
        }
        list.push(row)
      }
      return { accounts: list, ...(await settings()) }
    }
    case 'add':
      return add(msg)
    case 'unlock':
      return unlock(msg.password, msg.key)
    case 'awaitingKey':
      return awaitingKey()
    case 'finishKey':
      return finishKey(msg)
    case 'lock':
      return lock()
    case 'remove': {
      const all = await accounts()
      const a = all.find((x) => x.key === msg.key)
      if (a) await signOut(a)
      await chrome.storage.local.remove(`local:${msg.key}`)
      await chrome.storage.local.set({ accounts: all.filter((x) => x.key !== msg.key) })
      // Its save offers have nowhere to go now.
      for (const [k, p] of Object.entries(await chrome.storage.session.get(null))) {
        if (k.startsWith('pending:') && p?.key === msg.key) {
          await chrome.storage.session.remove(k)
          await badge(Number(k.slice(8)), false)
        }
      }
      return true
    }
    case 'settings':
      await chrome.storage.local.set({ settings: { lockMinutes: Number(msg.lockMinutes) || 10 } })
      // A new idle time counts from now (lockAt is set only while something is unlocked).
      if (await session('lockAt')) await touch()
      return true
    case 'sync': {
      // `ifOlderThan`: the popup's quiet refresh when it opens.
      if (msg.ifOlderThan && Date.now() - ((await session('lastSync')) ?? 0) < msg.ifOlderThan) return null
      const problems = []
      for (const [a, acct] of await unlocked()) {
        try {
          problems.push(...(await sync(a, acct)))
        } catch (e) {
          problems.push({ text: `${a.username} on ${hostOf(a.server)}: ${e.name === 'network' ? "couldn't reach the server" : e.message}` })
        }
      }
      await touch()
      return problems
    }
    case 'leaveCheck':
      return JSON.parse(await withAccount(msg.key, (acct) => acct.leaveCheck(msg.vault)))
    case 'leave': {
      const acct = await withAccount(msg.key, async (acct) => (await acct.leaveVault(msg.vault), acct))
      // The leave happened either way. If this save fails, the stored copy still
      // has the vault: after a restart it comes back until the next sync hides it
      // again, and if it had unsent changes, every sync reports it as no longer
      // listed for you.
      await save(msg.key, acct).catch(() => {})
      return true
    }
    case 'pending': {
      const p = await pending(msg.tabId)
      return p && { offer: p.offer, username: p.shown ?? p.username, host: hostOf(p.page) }
    }
    case 'savePending':
      return savePending(msg.tabId, msg.save)
    case 'list':
      await touch()
      return list(msg.tabId, msg.query ?? '')
    case 'item': {
      const [, acct] = (await unlocked()).find(([a]) => a.key === msg.key) ?? []
      if (!acct) throw fail('locked', 'Unlock Plaintext first.')
      await touch()
      return JSON.parse(acct.item(msg.vault, msg.id))
    }
    case 'fill':
      return fill(msg.tabId, msg.key, msg.vault, msg.id)
    case 'setExactHost': {
      const [a, acct] = (await unlocked()).find(([x]) => x.key === msg.key) ?? []
      if (!acct) throw fail('locked', 'Unlock Plaintext first.')
      try {
        await acct.setExactHost(msg.vault, msg.id, Boolean(msg.exact))
      } catch (e) {
        // Nothing changed (read-only vault, item gone).
        if (e.name === 'refused' || e.name === 'not_found') throw e
        // Changed here but not sent: kept on this device and sent at the next sync.
        await save(a.key, acct)
        if (e.name === 'network') return { queued: true }
        if (e.name === 'signed_out') {
          await forget(a.key)
          throw e
        }
        throw fail('not_sent', `${e.message}. The change is kept on this device and Plaintext tries again at the next sync.`)
      }
      await save(a.key, acct)
      return { saved: true }
    }
    case 'signupField':
      // Whether the page's focused field wants a new password (the popup then opens the generator).
      return chrome.tabs.sendMessage(msg.tabId, { action: 'signupField' }, { frameId: 0 }).then((r) => r === true, () => false)
    case 'fillPassword': {
      if (!(await tabPage(msg.tabId))) throw fail('refused', 'Plaintext fills only web pages (http and https).')
      const r = await fillTab(msg.tabId, { action: 'fillNew', password: msg.password })
      if (r?.result !== 'filled') throw fail('no_form', "This page has no new-password field to fill.")
      return true
    }
    case 'generate': {
      await ready
      const password = generate(JSON.stringify(msg.recipe))
      return { password, bits: strength(password) }
    }
    case 'totp': {
      await ready
      return JSON.parse(totp(msg.spec, Date.now() / 1000) ?? 'null')
    }
    case 'copied':
      chrome.alarms.create('clear-clipboard', { delayInMinutes: CLEAR_AFTER_S / 60 })
      return true
  }
  throw fail('refused', `unknown action ${msg.action}`)
}

/** Run `f(acct, a)` on an unlocked account; an ended session locks it again. */
async function withAccount(key, f) {
  const [a, acct] = (await unlocked()).find(([x]) => x.key === key) ?? []
  if (!acct) throw fail('locked', 'Unlock Plaintext first.')
  await touch()
  try {
    return await f(acct, a)
  } catch (e) {
    if (e.name === 'signed_out') await forget(a.key)
    throw e
  }
}

async function add({ server, secretKey, password }) {
  await ready
  const base = server.trim().replace(/\/+$/, '')
  if (insecureUrl(base)) {
    throw fail('refused', "That address isn't https://. Plain http:// works only on this computer and private networks, because anyone on the way could take over the sign-in.")
  }
  let added
  try {
    // Adding again an account this browser has keeps its security-key trust. Which
    // account the Secret Key names isn't known yet; the server takes only its own token.
    const trust = (await accounts()).find((x) => x.server === base && x.trust)?.trust
    added = await Account.add(send, base, password, secretKey, DEVICE, trust)
  } catch (e) {
    // The account is found by the Secret Key alone, so a wrong password comes back as a 401.
    if (e.name === 'tampered' || e.name === 'signed_out') throw fail('tampered', "That password and Secret Key don't match an account on this server. Check both, then try again.")
    throw e
  }
  const pending = added.pending()
  if (pending) return awaitKey(`new@${hostOf(base)}`, base, pending, { add: { sealed: added.sealedSecretKey() } })
  return addAccount(added.account(), base, added.sealedSecretKey())
}

async function addAccount(acct, base, sealed, trust) {
  const username = acct.username()
  const key = `${username}@${hostOf(base)}`
  const all = await accounts()
  trust ||= all.find((x) => x.key === key)?.trust
  const a = { key, server: base, username, sealed, ...(trust && { trust }) }
  const rest = all.filter((x) => x.key !== a.key)
  await chrome.storage.local.set({ accounts: [...rest, a] })
  await signOut(a)
  const problems = await settle(a, acct)
  await touch()
  return { username, problems }
}

// ---------- Signing in with a security key (DESIGN "Signing in with a security key") ----------

/** Keep a sign-in waiting for the account's security key in memory-only storage
 *  (the browser may stop this background while the approval page is open), and
 *  tell the page to open the approval page. */
async function awaitKey(key, server, pending, extra = {}) {
  const page = pending.page()
  await chrome.storage.session.set({ [`signin:${key}`]: { server, state: pending.state(), page, at: Date.now(), ...extra } })
  pending.free()
  // It holds the Account Unlock Key: gone once the server has forgotten it too.
  chrome.alarms.create('signin-expire', { delayInMinutes: SIGNIN_FOR_MS / 60_000 + 0.1 })
  return { key, server, ok: false, error: 'key_needed', page, message: 'This account needs your security key to sign in on this browser.' }
}

/** Sign-ins still waiting for a security key: [{key, page}]. */
async function awaitingKey() {
  const all = await chrome.storage.session.get(null)
  const out = []
  for (const [k, v] of Object.entries(all)) {
    if (!k.startsWith('signin:')) continue
    if (Date.now() - v.at > SIGNIN_FOR_MS) await chrome.storage.session.remove(k)
    else out.push({ key: k.slice(7), page: v.page, server: v.server })
  }
  return out
}

/** Finish once the approval page has the key's answer, or with a recovery code. */
async function finishKey({ key, recovery }) {
  await ready
  const k = `signin:${key}`
  const p = (await chrome.storage.session.get(k))[k]
  if (!p || Date.now() - p.at > SIGNIN_FOR_MS) {
    await chrome.storage.session.remove(k)
    throw fail('expired', 'This sign-in took too long. Unlock again to start over.')
  }
  const pending = PendingSignIn.restore(send, p.server, p.state)
  let acct, trust
  try {
    acct = await pending.finish(recovery || undefined)
    trust = pending.trust()
  } catch (e) {
    if (e.name === 'expired') await chrome.storage.session.remove(k)
    // The server may have finished it before the account failed to load: keep that, so trying again doesn't ask the key twice.
    else await chrome.storage.session.set({ [k]: { ...p, state: pending.state() } })
    throw e
  } finally {
    pending.free()
  }
  await chrome.storage.session.remove(k)
  if (p.add) return addAccount(acct, p.server, p.add.sealed, trust)
  const all = await accounts()
  const a = all.find((x) => x.key === key)
  if (!a) throw fail('refused', 'That account was removed from this browser meanwhile.')
  a.trust = trust
  await chrome.storage.local.set({ accounts: all })
  await signOut(a)
  const problems = await settle(a, acct)
  await touch()
  return { username: a.username, problems }
}

/** After signing in: this device's copies, then a sync. Neither failing undoes the sign-in. */
async function settle(a, acct) {
  const problems = []
  const copies = await local(`local:${a.key}`)
  if (copies) await acct.loadLocal(copies).catch((e) => problems.push({ text: `This device's saved copy couldn't be merged: ${e.message}` }))
  await remember(a, acct)
  // Kept now so a failed first sync can still be reopened offline; a copy that
  // didn't merge is left as it was.
  if (!problems.length) await save(a.key, acct)
  try {
    problems.push(...(await sync(a, acct)))
  } catch (e) {
    problems.push({ text: e.name === 'network' ? "Couldn't reach the server to sync; showing what this device has." : `Couldn't sync: ${e.message}` })
  }
  return problems
}

/** Unlock every account this password opens, or just the one `key` names.
 *  The one way in: anything else that unlocks (a security key, say) goes through here. */
async function unlock(password, key) {
  await ready
  const results = []
  for (const a of await accounts()) {
    if (key && a.key !== key) continue
    // Open here already (the popup's status opens what it can).
    if (open.has(a.key)) {
      results.push({ key: a.key, ok: true })
      continue
    }
    // Locked, or its session couldn't be picked up again: sign in afresh, which
    // checks the password. Only then is an old session ended, so a wrong
    // password leaves one that still works alone.
    let acct
    try {
      const r = await Account.unlock(send, a.server, password, a.sealed, DEVICE, a.trust)
      const pending = r.pending()
      if (pending) {
        results.push(await awaitKey(a.key, a.server, pending))
        continue
      }
      acct = r.account()
    } catch (e) {
      results.push({ key: a.key, ok: false, error: e.name, message: e.message })
      continue
    }
    await signOut(a)
    try {
      results.push({ key: a.key, ok: true, problems: await settle(a, acct) })
    } catch (e) {
      results.push({ key: a.key, ok: false, error: e.name, message: e.message })
    }
  }
  if (results.some((r) => r.ok)) await touch()
  return results
}

// ---------- Messages from content scripts (untrusted pages) ----------

async function fromContent(msg, sender) {
  const tabId = sender.tab?.id
  // Top frames only, and the page is whatever the browser says, not the message.
  if (tabId == null || sender.frameId !== 0 || !/^https?:/.test(sender.url ?? '')) return null
  await lockIfIdle()
  const page = sender.url
  switch (msg.action) {
    case 'submitted': {
      // A newer submit replaces any older offer, even when there's nothing to save.
      await chrome.storage.session.remove(`pending:${tabId}`)
      await badge(tabId, false)
      const username = String(msg.username ?? '').slice(0, 512)
      const password = String(msg.password ?? '')
      if (!password || password.length > 4096) return null
      // Prefer the account that already has this login; otherwise the first one.
      let pick = null
      for (const [a, acct] of await unlocked()) {
        const offer = acct.saveOffer(page, username, password)
        if (offer === 'known') return null
        // `none`: no username, and no single login of this site it could be for.
        if (offer === 'none') continue
        if (!pick || offer === 'update') pick = { key: a.key, offer, shown: acct.saveTarget(page, username) ?? username }
      }
      if (!pick) return null
      await chrome.storage.session.set({ [`pending:${tabId}`]: { ...pick, page, username, password, at: Date.now() } })
      await badge(tabId, true)
      return null
    }
    case 'loaded':
      // Browsers clear a tab's badge when it navigates, which most sign-ins do.
      await badge(tabId, Boolean(await pending(tabId)))
      return null
    case 'openPopup':
      try {
        await chrome.action.openPopup()
        return true
      } catch {
        return false
      }
  }
  return null
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (sender.id !== chrome.runtime.id || msg?.action === 'wipe-clipboard') return false
  const mine = (sender.url ?? '').startsWith(chrome.runtime.getURL(''))
  serial(() => (mine ? fromPage(msg) : fromContent(msg, sender))).then(
    (ok) => reply({ ok }),
    (e) => reply({ error: { name: e?.name ?? 'error', message: e?.message ?? String(e) } }),
  )
  return true
})

// ---------- Keyboard shortcut ----------

chrome.commands.onCommand.addListener((command, tab) => {
  if (command !== 'fill' || !tab?.id) return
  serial(async () => {
    await lockIfIdle()
    const { rows } = await list(tab.id, '')
    const best = rows.find((r) => r.here && r.has_password)
    if (!best) return chrome.action.openPopup().catch(() => {})
    return fill(tab.id, best.account, best.vault, best.id)
  }).catch(() => {})
})

chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove(`pending:${tabId}`))

// First install: straight to adding an account.
chrome.runtime.onInstalled.addListener(({ reason }) => reason === 'install' && chrome.runtime.openOptionsPage())
