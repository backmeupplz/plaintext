// The packaged Firefox extension end to end against a local server (see run.sh),
// through geckodriver with --allow-system-access: Firefox keeps extension pages
// away from WebDriver otherwise.
//   node firefox.mjs <xpi> <server> <secret key> <password> <shots dir>
// FIREFOX_PATH: a Firefox binary.
import { Builder, By, until } from 'selenium-webdriver'
import firefox from 'selenium-webdriver/firefox.js'
import { mkdirSync, writeFileSync } from 'node:fs'

const [xpi, server, secretKey, password, shots] = process.argv.slice(2)
mkdirSync(shots, { recursive: true })
const UUID = 'b7d3f0a2-1c4e-4f5a-9b8c-0d1e2f3a4b5c'
const EXT = `moz-extension://${UUID}`
const SITE = 'http://localhost:8090'
const theme = process.env.DARK ? 'dark' : 'light'
const opts = new firefox.Options()
opts.setBinary(process.env.FIREFOX_PATH)
if (!process.env.HEADFUL) opts.addArguments('-headless')
opts.setPreference('extensions.webextensions.uuids', JSON.stringify({ 'plaintext@getplaintext.org': UUID }))
opts.setPreference('ui.systemUsesDarkTheme', theme === 'dark' ? 1 : 0)
opts.setPreference('layout.css.prefers-color-scheme.content-override', theme === 'dark' ? 0 : 1)
opts.windowSize({ width: 1000, height: 800 })
const d = await new Builder().forBrowser('firefox').setFirefoxOptions(opts).setFirefoxService(new firefox.ServiceBuilder().addArguments('--allow-system-access')).build()
await d.installAddon(xpi, true)
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
let failures = 0
const check = (ok, what) => (ok ? console.log('[firefox] ok  ', what) : (failures++, console.log('[firefox] FAIL', what)))
const shot = async (name) => {
  const popupPage = (await d.getCurrentUrl()).includes('/popup.html')
  const png = popupPage ? await d.findElement(By.css('body')).takeScreenshot() : await d.takeScreenshot()
  writeFileSync(`${shots}/${name}-${theme}.png`, png, 'base64')
}
const $ = (css) => d.findElement(By.css(css))
const js = (fn, ...args) => d.executeScript(`return (${fn})(...arguments)`, ...args)
const jsAsync = (fn, ...args) => d.executeAsyncScript(`const done = arguments[arguments.length - 1]; (${fn})(...Array.from(arguments).slice(0, -1)).then(done, (e) => done('ERR ' + e))`, ...args)

// Settings: the extension opens it on install (automation may not navigate to extension pages).
let setupHandle
await d.wait(async () => {
  for (const h of await d.getAllWindowHandles()) {
    await d.switchTo().window(h)
    if ((await d.getCurrentUrl()).endsWith('/setup.html')) return (setupHandle = h)
  }
  return false
}, 15000)
await $('#server').sendKeys(server)
await $('#sk').sendKeys(secretKey)
await $('#pw').sendKeys(password)
await shot('01-settings-add')
await $('#add-btn').click()
await d.wait(async () => /Signed in|error|match|reach/i.test(await $('#add-msg').getText()) && (await $('#add-btn').isEnabled()), 60000).catch(() => {})
const added = await $('#add-msg').getText()
check(/Signed in as alice/.test(added), `sign in (${added})`)
await shot('02-settings-signed-in')

// The site, in its own window, so the popup has a page to work on.
await d.switchTo().newWindow('window')
const siteHandle = await d.getWindowHandle()
async function site(path) {
  await d.switchTo().window(siteHandle)
  if (path) await d.get(`${path.startsWith('http') ? '' : SITE}${path}`)
}
async function popup() {
  await site()
  const before = await d.getAllWindowHandles()
  await d.switchTo().window(setupHandle)
  // Focus the site's window first, as when the toolbar button is clicked over it.
  await jsAsync(async () => {
    const [t] = await chrome.tabs.query({ url: ['http://localhost/*', 'http://127.0.0.1/*'] })
    await chrome.windows.create({ url: `popup.html?tab=${t.id}`, type: 'popup', width: 360, height: 620 })
  })
  let handle
  await d.wait(async () => (handle = (await d.getAllWindowHandles()).find((h) => !before.includes(h))), 10000)
  await d.switchTo().window(handle)
  await d.wait(until.elementLocated(By.css('main > *')), 15000)
  await sleep(500)
  return handle
}
const closePopup = async () => {
  await d.close()
  await site()
}

await site('/login')
await js(() => document.querySelector('[name=password]').focus())
await popup()
await d.wait(until.elementLocated(By.css('.row')), 15000)
check((await d.findElements(By.css('.generated'))).length === 0, "a login page's password field opens the list, not the generator")
await shot('03-popup-site-first')
check((await $('.list h2').getText()).toLowerCase() === 'on localhost:8090', "site's logins first")
check((await js(() => document.activeElement?.id)) === 'search', 'search is focused')
await $('.row button.primary').click()
await sleep(1200)
await site()
const filled = await js(() => [document.querySelector('[name=email]').value, document.querySelector('[name=password]').value])
check(filled[0] === 'alice@example.com' && filled[1] === 'hunter2-demo', 'one-click fill')
await shot('04-site-filled')

await popup()
await d.wait(until.elementLocated(By.css('.row')), 15000)
await $('.row .row-text').click()
await d.wait(until.elementLocated(By.css('.fields')), 5000)
await shot('05-popup-item')
await closePopup()

await site('/signup')
await $('[name=email]').sendKeys('new@example.com')
await popup()
check((await d.findElements(By.css('.list'))).length === 1, 'the list on a signup page while the email field is focused')
await closePopup()
await js(() => document.querySelector('[name=pw1]').focus())
await popup()
await d.wait(async () => (await $('.generated').getText()).length >= 20, 5000)
await shot('07-popup-generator')
const generated = await $('.generated').getText()
await $('.buttons .primary').click()
await sleep(1000)
await site()
const pw = await js(() => [document.querySelector('[name=pw1]').value, document.querySelector('[name=pw2]').value])
check(pw[0] === generated && pw[1] === generated, 'generated password filled')
await $('button[type=submit]').click()
await d.wait(until.elementLocated(By.css('#got')), 10000)
await sleep(1500)
await shot('08-site-after-signup')
check((await js(() => document.querySelector('plaintext-ui'))) === null, 'the save offer adds nothing to the page')
await popup()
await d.wait(until.elementLocated(By.css('.banner.offer')), 10000)
await shot('09-popup-save-offer')
await $('.banner.offer button.primary').click()
await sleep(2000)
await shot('10-popup-saved')
await closePopup()

await popup()
await d.wait(until.elementLocated(By.css('.row')), 15000)
await $('#search').sendKeys('new@example.com')
await sleep(500)
const saved = await Promise.all((await d.findElements(By.css('.row .title'))).map((e) => e.getText()))
check(saved.includes('localhost'), `new login saved (${saved})`)
await closePopup()

await site('/offsite')
await popup()
await d.wait(until.elementLocated(By.css('.row button.primary')), 15000)
await $('.row button.primary').click()
await sleep(1200)
const msg = await $('#status').getText()
await site()
check((await js(() => document.querySelector('[name=password]').value)) === '', `no fill into a form posting elsewhere (${msg})`)

for (const path of ['/formaction', '/outside', '/mailto', '/image']) {
  await site(path)
  await popup()
  await d.wait(until.elementLocated(By.css('.row button.primary')), 15000)
  await $('.row button.primary').click()
  await sleep(1200)
  await closePopup().catch(() => site())
  check((await js(() => document.querySelector('[name=password]').value)) === '', `no fill when the form can go elsewhere (${path})`)
}

await site('/scripted')
await popup()
await d.wait(until.elementLocated(By.css('.row button.primary')), 15000)
await $('.row button.primary').click()
await sleep(1200)
await site()
check((await js(() => document.querySelector('[name=password]').value)) === 'hunter2-demo', 'fills a form its own script submits (javascript: action)')

await site('http://127.0.0.1:8091/frame')
await popup()
await sleep(800)
check((await d.findElements(By.css('.row button.primary'))).length === 0, 'no fill for a login framed by another site')
await $('[aria-label="Lock"]').click()
await d.wait(until.elementLocated(By.css('#pw')), 10000)
await shot('12-popup-locked')
await $('#pw').sendKeys(password)
await $('button[type=submit]').click()
await d.wait(until.elementLocated(By.css('#search')), 30000)
check(true, 'unlock with the password only')
await shot('14-popup-unlocked-other-site')
await closePopup()

// A second account with another password: unlocked on its own from the list.
await d.switchTo().window(setupHandle)
await $('#server').clear()
await $('#server').sendKeys(server)
await $('#sk').sendKeys(process.env.BOB_SK)
await $('#pw').sendKeys("bob's own password")
await $('#add-btn').click()
await d.wait(async () => /Signed in as bob/.test(await $('#add-msg').getText()), 60000).catch(() => {})
await popup()
await $('[aria-label="Lock"]').click()
await d.wait(until.elementLocated(By.css('#pw')), 10000)
await $('#pw').sendKeys(password)
await $('button[type=submit]').click()
await d.wait(until.elementLocated(By.css('.locked-account')), 30000)
await sleep(300)
await shot('15-popup-one-locked')
check(/bob on localhost:8080 is locked/.test(await $('.locked-account').getText()), 'the account with another password stays locked and says so')
await $('.locked-account button.small:not(.primary)').click()
await $('.locked-account input[type=password]').sendKeys("bob's own password")
await $('.locked-account button.primary').click()
const titles = async () => Promise.all((await d.findElements(By.css('.row .title'))).map((e) => e.getText()))
await d.wait(async () => (await d.findElements(By.css('.locked-account'))).length === 0 && (await titles()).includes("Bob's shop"), 30000).catch(() => {})
check((await d.findElements(By.css('.locked-account'))).length === 0 && (await titles()).includes("Bob's shop"), 'unlock the second account with its own password')
await shot('16-popup-both-unlocked')

await d.quit()
console.log(failures ? `[firefox] ${failures} FAILED` : '[firefox] all passed')
process.exit(failures ? 1 : 0)
