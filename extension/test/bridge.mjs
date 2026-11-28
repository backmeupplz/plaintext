// Drives the built WebAssembly (pkg/) through the extension's own fetch glue
// against a real server. Run by `cargo test -p plaintext-wasm --test extension`
// with the server, account and expectations set up in Rust (wasm/tests/extension.rs).
//   node test/bridge.mjs <server> <password> <secret key>
import { readFile } from 'node:fs/promises'
import { initSync, Account, generate, strength } from '../pkg/plaintext_wasm.js'
import { send } from '../lib/net.js'

const [server, password, secretKey] = process.argv.slice(2)
initSync({ module: await readFile(new URL('../pkg/plaintext_wasm_bg.wasm', import.meta.url)) })
const out = {}
const page = 'https://github.com/login'

const added = await Account.add(send, server, password, secretKey, 'Node test')
const sealed = added.sealedSecretKey()
let acct = added.account()
out.username = acct.username()
out.problems = JSON.parse(await acct.sync())
const rows = JSON.parse(acct.list(page, ''))
out.first = rows[0]
out.fill = JSON.parse(acct.fill(rows[0].vault, rows[0].id, page))
try {
  acct.fill(rows[0].vault, rows[0].id, 'https://evil.example/login')
} catch (e) {
  out.crossSite = e.name
}
out.offer = acct.saveOffer('https://example.com/signup', 'new@example.com', 'pw1')
out.saved = JSON.parse(await acct.saveLogin('https://example.com/signup', 'new@example.com', 'pw1'))

// Overlapping calls fail cleanly instead of corrupting state.
const a = acct.sync()
try {
  await acct.sync()
} catch (e) {
  out.overlap = e.name
}
await a

// The background was suspended: resume from storage.session + storage.local.
const session = acct.sessionState()
const local = acct.localState()
acct = await Account.resume(send, server, session)
await acct.loadLocal(local)
out.afterResume = JSON.parse(acct.list(null, 'example')).length
// Or offline, from what the extension stored.
out.restored = JSON.parse(Account.restore(send, 'http://127.0.0.1:9', session, local).list(page, ''))[0].title

try {
  await Account.unlock(send, server, 'wrong password', sealed, 'Node test')
} catch (e) {
  out.wrongPassword = e.name
}
const again = (await Account.unlock(send, server, password, sealed, 'Node test')).account()
out.unlocked = again.username()
const [status] = await send('POST', `${server}/v1/logout`, JSON.parse(again.sessionState()).token)
out.logout = status

out.generated = generate(JSON.stringify({ type: 'random', length: 24, digits: true, symbols: true })).length
out.strong = strength('correct horse battery staple') > 40
console.log(JSON.stringify(out))
