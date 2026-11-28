// The packaged Chrome extension end to end against a local server (see run.sh).
//   node chrome.mjs chrome <dist dir> <server> <secret key> <password> <shots dir>
// CHROME_PATH: a Chrome for Testing binary (branded Chrome can't load unpacked extensions from automation).
import puppeteer from 'puppeteer-core'
import { mkdirSync } from 'node:fs'

const [browserName, dist, server, secretKey, password, shots] = process.argv.slice(2)
mkdirSync(shots, { recursive: true })
const SITE = 'http://localhost:8090'
const log = (...a) => console.log(`[${browserName}]`, ...a)
const browser = await puppeteer.launch({
  browser: browserName,
  executablePath: process.env.CHROME_PATH,
  headless: process.env.HEADFUL ? false : true,
  enableExtensions: true,
  pipe: browserName === 'chrome',
  args: browserName === 'chrome' ? ['--window-size=1200,900'] : [],
  extraPrefsFirefox: { 'extensions.webextensions.uuids': JSON.stringify({ 'plaintext@getplaintext.org': 'b7d3f0a2-1c4e-4f5a-9b8c-0d1e2f3a4b5c' }), 'extensions.openPopupWithoutUserGesture.enabled': true, 'ui.systemUsesDarkTheme': process.env.DARK ? 1 : 0 },
})
const id = await browser.installExtension(dist)
const base = browserName === 'chrome' ? `chrome-extension://${id}` : 'moz-extension://b7d3f0a2-1c4e-4f5a-9b8c-0d1e2f3a4b5c'
log('installed', id)


let failures = 0
function check(cond, what) {
  if (cond) log('ok  ', what)
  else {
    failures++
    log('FAIL', what)
  }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const theme = process.env.DARK ? 'dark' : 'light'

// Settings page (opens itself in Firefox via the extension's own URL).
// The extension opens its settings on install.
const setupTarget = await browser.waitForTarget((t) => t.url().endsWith('/setup.html'), { timeout: 15000 })
const setup = await setupTarget.asPage()
log('extension base', base)
await setup.setViewport({ width: 800, height: 900 })
await setup.emulateMediaFeatures([{ name: 'prefers-color-scheme', value: theme }])
await setup.type('#server', server)
await setup.type('#sk', secretKey)
await setup.type('#pw', password)
await setup.screenshot({ path: `${shots}/01-settings-add-${theme}.png` })
await setup.click('#add-btn')
await setup.waitForFunction(() => /Signed in|error|permission|match|reach/i.test(document.querySelector('#add-msg').textContent) && !document.querySelector('#add-btn').disabled, { timeout: 60000 }).catch(() => {})
const added = await setup.$eval('#add-msg', (e) => e.textContent)
log('add:', added)
check(/Signed in as alice/.test(added), 'sign in with server, Secret Key and password')
await setup.screenshot({ path: `${shots}/02-settings-signed-in-${theme}.png` })

async function popup() {
  await setup.evaluate(async () => { const [t] = await chrome.tabs.query({ url: ['http://localhost/*', 'http://127.0.0.1/*'] }); await chrome.windows.create({ url: `popup.html?tab=${t.id}`, type: 'popup', width: 360, height: 600, focused: false }) })
  const t = await browser.waitForTarget((t) => t.url().includes('/popup.html'), { timeout: 10000 })
  const p = await t.asPage()
  await p.setViewport({ width: 360, height: 560 })
  await p.emulateMediaFeatures([{ name: 'prefers-color-scheme', value: theme }])
  await p.waitForSelector('main > *', { timeout: 15000 })
  return p
}

// Fill on the login page.
const site = await browser.newPage()
await site.goto(`${SITE}/login`)
await site.bringToFront()
await site.focus('[name=password]')
let p = await popup()
await p.waitForSelector('.row', { timeout: 15000 })
await sleep(300)
await p.screenshot({ path: `${shots}/03-popup-site-first-${theme}.png` })
const heading = await p.$eval('.list h2', (e) => e.textContent)
check(heading === 'On localhost:8090', `site's logins first ("${heading}")`)
const focused = await p.evaluate(() => document.activeElement?.id)
check(focused === 'search', 'search is focused')
check(!(await p.$('.generated')), 'a login page\'s password field opens the list, not the generator')
await p.click('.row button.primary')
await sleep(1000)
const filled = await site.evaluate(() => [document.querySelector('[name=email]').value, document.querySelector('[name=password]').value])
check(filled[0] === 'alice@example.com' && filled[1] === 'hunter2-demo', 'one-click fill')
await site.screenshot({ path: `${shots}/04-site-filled-${theme}.png` })

// Item view, from a fresh popup.
p = await popup()
await p.waitForSelector('.row')
await p.click('.row .row-text')
await p.waitForSelector('.fields')
await p.screenshot({ path: `${shots}/05-popup-item-${theme}.png` })

// Copy, then the clear (its alarm fired now instead of in 90 s) empties the clipboard.
await browser.defaultBrowserContext().overridePermissions(base, ['clipboard-read', 'clipboard-sanitized-write'])
await (await p.createCDPSession()).send('Emulation.setFocusEmulationEnabled', { enabled: true })
const clipboard = () => p.evaluate(() => navigator.clipboard.readText())
await p.click('[aria-label="Copy password"]')
await sleep(300)
check((await clipboard()) === 'hunter2-demo', 'copy a password')
const worker = await (await browser.waitForTarget((t) => t.type() === 'service_worker' && t.url().startsWith(base))).worker()
await worker.evaluate(() => chrome.alarms.create('clear-clipboard', { when: Date.now() }))
await sleep(2000)
check((await clipboard()) === '', 'the copied password is cleared from the clipboard')
await p.close().catch(() => {})

// Search and the generator.
p = await popup()
await p.waitForSelector('.row')
await p.type('#search', 'goo')
await sleep(400)
await p.screenshot({ path: `${shots}/06-popup-search-${theme}.png` })
const results = await p.$$eval('.row .title', (e) => e.map((x) => x.textContent))
check(results.length === 1 && results[0] === 'Google', `search ("goo" → ${results})`)
await p.close().catch(() => {})

// Signup: a new-password field opens the generator, then save after submit.
await site.goto(`${SITE}/signup`)
await site.type('[name=email]', 'new@example.com')
p = await popup()
check(Boolean(await p.$('.list')), 'the list on a signup page while the email field is focused')
await p.close().catch(() => {})
await site.focus('[name=pw1]')
p = await popup()
await p.waitForFunction(() => document.querySelector('.generated')?.textContent.length >= 20)
await p.screenshot({ path: `${shots}/07-popup-generator-${theme}.png` })
const generated = await p.$eval('.generated', (e) => e.textContent)
await p.click('.buttons .primary')
await sleep(800)
const pw = await site.evaluate(() => [document.querySelector('[name=pw1]').value, document.querySelector('[name=pw2]').value])
check(pw[0] === generated && pw[1] === generated, 'generated password filled into both new-password fields')
await site.bringToFront()
await site.click('button[type=submit]')
await site.waitForSelector('#got')
await sleep(1500)
await site.screenshot({ path: `${shots}/08-site-after-signup-${theme}.png` })
check((await site.evaluate(() => document.querySelector('plaintext-ui'))) === null, 'the save offer adds nothing to the page')
p = await popup()
await p.waitForSelector('.banner.offer', { timeout: 10000 })
await p.screenshot({ path: `${shots}/09-popup-save-offer-${theme}.png` })
await p.click('.banner.offer button.primary')
await sleep(2000)
await p.screenshot({ path: `${shots}/10-popup-saved-${theme}.png` })
await p.close().catch(() => {})

p = await popup()
await p.waitForSelector('.row')
await p.type('#search', 'new@example.com')
await sleep(500)
const saved = await p.$$eval('.row .title', (e) => e.map((x) => x.textContent))
check(saved.includes('localhost'), `new login saved (${saved})`)
await p.close().catch(() => {})

// Never fill a form that posts to another site, or a login framed by another site.
await site.goto(`${SITE}/offsite`)
p = await popup()
await p.waitForSelector('.row button.primary')
await p.click('.row button.primary')
await sleep(1000)
const offsite = await site.evaluate(() => document.querySelector('[name=password]').value)
const msg = await p.$eval('#status', (e) => e.textContent).catch(() => '')
check(offsite === '', `no fill into a form posting to another site (${msg})`)
await p.screenshot({ path: `${shots}/11-offsite-refused-${theme}.png` })
await p.close().catch(() => {})

for (const path of ['/formaction', '/outside', '/mailto', '/image']) {
  await site.goto(`${SITE}${path}`)
  p = await popup()
  await p.waitForSelector('.row button.primary')
  await p.click('.row button.primary')
  await sleep(1000)
  check((await site.evaluate(() => document.querySelector('[name=password]').value)) === '', `no fill when the form can go elsewhere (${path})`)
  await p.close().catch(() => {})
}

await site.goto(`${SITE}/scripted`)
p = await popup()
await p.waitForSelector('.row button.primary')
await p.click('.row button.primary')
await sleep(1000)
check((await site.evaluate(() => document.querySelector('[name=password]').value)) === 'hunter2-demo', 'fills a form its own script submits (javascript: action)')

await site.goto('http://127.0.0.1:8091/frame')
p = await popup()
await p.waitForSelector('.list')
await sleep(500)
const fillButtons = await p.$$('.row button.primary')
check(fillButtons.length === 0, 'no fill offered for a login framed by another site')
await p.close().catch(() => {})

// Lock.
p = await popup()
await p.click('[aria-label="Lock"]')
await p.waitForSelector('#pw')
await p.screenshot({ path: `${shots}/12-popup-locked-${theme}.png` })
await p.type('#pw', 'wrong password')
await p.click('button[type=submit]')
await p.waitForFunction(() => document.querySelector('.error')?.textContent, { timeout: 30000 })
await p.screenshot({ path: `${shots}/13-popup-wrong-password-${theme}.png` })
check(/didn.t match/.test(await p.$eval('.error', (e) => e.textContent)), 'wrong password says so')
await p.$eval('#pw', (e) => (e.value = ''))
await p.type('#pw', password)
await p.click('button[type=submit]')
await p.waitForSelector('#search', { timeout: 30000 })
check(true, 'unlock with the password only')
await p.close().catch(() => {})

// A second account with another password: unlocked on its own from the list.
await setup.bringToFront()
await setup.$eval('#server', (e) => (e.value = ''))
await setup.type('#server', server)
await setup.type('#sk', process.env.BOB_SK)
await setup.type('#pw', "bob's own password")
await setup.click('#add-btn')
await setup.waitForFunction(() => /Signed in as bob/.test(document.querySelector('#add-msg').textContent), { timeout: 60000 }).catch(() => {})
p = await popup()
await p.click('[aria-label="Lock"]')
await p.waitForSelector('#pw')
await p.type('#pw', password)
await p.click('button[type=submit]')
await p.waitForSelector('.locked-account', { timeout: 30000 })
await sleep(300)
await p.screenshot({ path: `${shots}/14-popup-one-locked-${theme}.png` })
check(/bob on localhost:8080 is locked/.test(await p.$eval('.locked-account', (e) => e.textContent)), 'the account with another password stays locked and says so')
await p.click('.locked-account button.small:not(.primary)')
await p.type('.locked-account input[type=password]', "bob's own password")
await p.click('.locked-account button.primary')
await p.waitForFunction(() => !document.querySelector('.locked-account') && [...document.querySelectorAll('.row .title')].some((t) => t.textContent === "Bob's shop"), { timeout: 30000 }).catch(() => {})
check(!(await p.$('.locked-account')) && (await p.$$eval('.row .title', (e) => e.map((x) => x.textContent))).includes("Bob's shop"), 'unlock the second account with its own password')
await p.screenshot({ path: `${shots}/15-popup-both-unlocked-${theme}.png` })

await browser.close()
log(failures ? `${failures} FAILED` : 'all passed')
process.exit(failures ? 1 : 0)
