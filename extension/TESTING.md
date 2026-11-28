# Testing the Plaintext extension

This is the first test build for Chrome and Firefox. It signs in to an existing Plaintext account, fills logins, saves new ones and generates passwords. You create accounts and edit items in the CLI or the apps; the extension doesn't do either yet.

## Install

The test builds are handed over as files, not through a store: `plaintext-chrome-….zip` and `plaintext-firefox-….xpi` in `~/Downloads/plaintext-test/`.

**Chrome (or Chromium, Edge, Brave, Arc):**
1. Unzip `plaintext-chrome-….zip`.
2. Open `chrome://extensions` and turn on **Developer mode** (top right).
3. Click **Load unpacked** and pick the unzipped folder.
4. Pin Plaintext to the toolbar from the puzzle-piece menu.

**Firefox:** the build isn't signed, so Firefox loads it only for the session. Open `about:debugging#/runtime/this-firefox`, click **Load Temporary Add-on…** and pick the `.xpi`. It's removed when Firefox quits. Firefox Developer Edition and Nightly can keep it installed: set `xpinstall.signatures.required` to `false` in `about:config`, then open the `.xpi`.

Settings open by themselves after installing. Later you can reach them from the gear in the popup, or from the extension's **Options**.

## Sign in

Enter the server address, your Secret Key and your password from your Emergency Kit. After that, the Secret Key stays in this browser, encrypted with your password, so unlocking takes only the password.

- The address must be `https://`. Plain `http://` works only for this computer, private networks and `.local`/`.ts.net` names.
- To use several accounts, add each one. A single password unlocks every account that uses it. An account with a different password stays locked, and the popup lists it above your items with its own **Unlock** button.

## What to try

1. **Fill.** Open a site you have a login for and click the Plaintext button. That site's logins come first, under "On *site*". Click **Fill**, or press **⌘⇧L** (Mac) or **Ctrl+Shift+L** (elsewhere) on the page to fill the best match without opening the popup.
2. **The mark in login fields.** Clicking into a username or password field shows a small Plaintext mark. Clicking it opens the popup (in Chrome 127 and later). Filling always happens from the popup or the shortcut, never from something drawn on the page.
3. **Search and copy.** The search field is focused as soon as the popup opens, and ↓ moves into the list. The person and copy icons copy the username and password. Copied secrets are cleared from the clipboard after 90 seconds.
4. **The item view.** Click a row to see its fields, reveal the password, copy the one-time code and open the website. **Fill only on *host*** makes that login fill only on its exact host, not the rest of its site.
5. **The generator.** The wand in the popup makes a password. On a sign-up form, click into the new password field first (or click the mark in it): the popup then opens straight on the generator. **Use on this page** puts the password into the form's new-password fields.
6. **Saving.** After you sign in or sign up somewhere with a login Plaintext doesn't have, the Plaintext button shows a badge. Open the popup to save the login, or to update the password if that username is already saved for the site. A password-only step or a change-password form with no username updates the site's login if it has exactly one, and offers nothing otherwise. Nothing appears in the page itself, so a site can't see or fake the offer. New logins go to your own default vault.
7. **Locking.** The lock icon locks right away. Plaintext also locks after the idle time you set in settings (10 minutes by default), and when the browser quits.

## What it deliberately doesn't do

- **Frames and other sites.** It never fills inside frames, and it never fills a form that sends the password to a different site than the page.
- **https logins on http pages.** A login saved for an `https://` site is never offered to the plain `http://` version of that page.
- **Shared vaults.** It never saves new logins into a vault someone shared with you.

## Known gaps in this build

- **Offline.** Unlocking needs the server. Once unlocked, the popup keeps working from this browser's copy when the server is unreachable, but nothing syncs until it's back.
- **Editing.** Editing items, creating accounts, passkeys, attachments, sharing and Watchtower live in the apps and CLI.
- **On Linux,** check that a copied password is gone from the clipboard after 90 seconds (Wayland included), and that the popup fits at your display scaling.
- **The keyboard shortcut** can be changed at `chrome://extensions/shortcuts`, or in Firefox at `about:addons` → gear → **Manage Extension Shortcuts**.

## A local server to test against

```sh
cargo run -p plaintext-server &        # http://localhost:8080
PLAINTEXT_SEED=http://localhost:8080 cargo test -p plaintext-wasm --test extension seed -- --ignored --nocapture
```

The second command creates `alice` with the password `correct horse battery staple` and a few demo logins, and `bob` with the password `bob's own password`. It prints both Secret Keys. The "Demo shop" login is saved for `http://localhost:8090`; set `PLAINTEXT_SEED_SITE` to use another address.

## Building

```sh
wasm/build.sh extension          # Rust core → extension/pkg (Docker on non-Linux hosts)
python3 extension/package.py 4   # extension/dist: chrome/, firefox/, the .zip and the unsigned .xpi (version 0.1.0.4)
```

You can load `extension/dist/chrome` unpacked in Chrome, and `extension/dist/firefox` (or the `.xpi`) as a temporary add-on in Firefox.

## Automated tests

- **CI:** `cargo test` covers the Rust bridge natively. CI also builds the WebAssembly, runs it under Node against a real server through the extension's own `fetch` code (`wasm/tests/extension.rs`), packages both builds and lints the Firefox one with `web-ext lint`.
- **Browsers:** `extension/test/browsers/run.sh` drives both browsers against a fresh local server. It signs in, fills, refuses off-site and framed forms, opens the generator from a sign-up form's password field and fills it, saves the new login from the popup, locks and unlocks, then unlocks a second account that has another password. It writes screenshots as it goes. It needs `npm ci --prefix extension/test/browsers`, a Chrome for Testing binary in `CHROME_PATH` and Firefox in `FIREFOX_PATH`.
