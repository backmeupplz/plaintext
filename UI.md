# Plaintext UI and UX

Every Plaintext app follows this document, so the iPhone, Mac, Android and browser versions feel like one product. Each app should still feel native: use the platform's own controls, navigation, sheets, haptics and type scale, and carry Plaintext's identity through color, typography, iconography and copy rather than through custom widgets.

The bar is "calm, fast and obvious". Opening the app, finding a login and copying the password should take under three seconds and no thought.

## Identity

| Token | Light | Dark | Use |
|---|---|---|---|
| `bg` | `#fbfbf8` | `#111110` | window and screen background |
| `surface` | `#f3f2ec` | `#191917` | cards, list groups, sidebars |
| `code` | `#efeee7` | `#1d1d1b` | secrets, fields shown in monospace |
| `line` | `#e4e3dc` | `#282825` | separators, borders |
| `fg` | `#1b1b19` | `#ecebe5` | primary text |
| `muted` | `#66665f` | `#9a9991` | secondary text, labels |
| `accent` | `#1f7a4d` | `#4cc38a` | primary actions, selection, the "text" in the wordmark |
| `accent-fg` | `#ffffff` | `#0d1f16` | text on accent |
| `warn` | `#b4561c` | `#f0a060` | Watchtower findings, "not verified" |
| `danger` | `#b42318` | `#f97066` | destructive actions |

- **Type.** The platform's system font for everything (SF Pro, Roboto/Google Sans, Segoe UI); the platform's monospace (SF Mono, Roboto Mono, Cascadia/Consolas) for passwords, one-time codes, Secret Keys, fingerprints and the `plaintext` wordmark. Support Dynamic Type / font scaling everywhere.
- **Wordmark.** `plain` in `fg` + `text` in `accent`, monospace, bold. App icon: the keyhole mark from `docs/favicon.svg` on accent green.
- **Corners and spacing.** 10–14 pt radius on cards and sheets, 8 pt on buttons and fields; spacing on a 4 pt grid; generous list row height (≥ 52 pt) so rows are easy targets.
- **Icons.** SF Symbols on Apple, Material Symbols (rounded) on Android, Lucide in the extension. Item kinds get a consistent icon set (login, card, note, identity, key, server, wifi, document, passport…). Never fetch website favicons: that leaks your list of sites (Bitwarden's BW06). Show a monogram tile (first letter of the title on a tint derived from the title) instead.
- **Motion.** Short and purposeful (150–250 ms). Copying a field gives a check animation and a light haptic. Respect Reduce Motion.

## Voice

Plain, warm, specific. Full sentences in explanations; short labels on buttons ("Copy password", "Share vault", "Save"). Never blame the user. Errors say what happened and what to do next ("That password didn't match. Check it and your Secret Key, then try again."). Security warnings explain the consequence in one sentence, not a lecture. No staccato fragments in marketing copy.

## Core screens

### First run

1. **Welcome**: wordmark, one sentence ("Your passwords, encrypted on your devices. Your server only ever sees ciphertext."), two buttons: *Create account* and *Sign in*.
2. **Server**: two choices.
   - **Plaintext Cloud**, which we host. It's a preset address, so there's nothing to type.
   - **My own server**, a field for any address: a domain, an IP or a Tailscale name, with an optional port. The note under it says this is the Plaintext server they or their family run. `http://` is accepted only for localhost, private networks and `.local`/`.ts.net` names, with a one-line warning that anyone on the network can see which server they use.

   Remember recent servers. Call `GET /v1/info` before moving on; it doubles as the reachability check.
3. **Create account**: username, then password with a live strength meter and a *Suggest one* button (memorable words). What else it asks for depends on `/v1/info`:
   - `setup`: a *Setup code* field, with a sentence saying it's the code the person who runs the server set.
   - Not `open`: an invite-code field, or the code arrives pre-filled from an invite link/QR.
   - `open`: an optional invite code, offered only when the user arrived from an invite link.
4. **Emergency Kit**: the Secret Key in large monospace, server address and username, an explanation in two sentences of why it matters and that nobody can recover it. Actions: *Save as PDF*, *Print*, *I've saved it*. The PDF has a blank line to write the password on. Don't let them continue without one of those taps.
5. **Unlock with Face ID / Touch ID / fingerprint**: offer it right away, with a one-line explanation.

**Several accounts.** One app holds any number of accounts, on the same server or different ones (a family server, a work server, Plaintext Cloud). Settings → Accounts lists them by username and server, with *Add account* (the same Server → Create/Sign in flow) and *Sign out of this account*. Unlock opens all of them at once.

- Home shows every account's vaults together. The vault picker groups them by account, and with more than one account each row's secondary line names the account.
- New items go to the default vault of the account selected in the picker.
- Sharing, people search and the Inbox are per account, because vaults can't be shared across servers.
- *Move to vault* can move an item to another account's vault, which re-encrypts it there.

**Sign in on a new device:** server → username → *Scan from another device* (QR shown by any signed-in device under Settings → Add a device, containing server, username and Secret Key) or *Enter Secret Key* → password. The QR path is the default; typing the key is the fallback.

### Unlock

Biometric prompt immediately on launch; a password field below it as the fallback. Auto-lock after a user-chosen idle time (default 10 minutes) and on device lock. The app switcher snapshot is blurred.

### Home (item list)

- A search field always at the top, focused on desktop and in the extension. Search matches title, username, URL, tags and non-secret fields, instantly, as you type.
- Sections: **Favorites**, then all items sorted by title (or most recently used, a toggle). A vault picker (All vaults / each vault) in the sidebar on Mac/iPad and in a menu on phones.
- Each row: monogram tile, title, secondary line (username, or card's last four, or note preview), and on hover/long-press the quick actions *Copy username*, *Copy password*, *Copy one-time code*.
- Swipe actions on phones: copy password (leading), favorite / archive (trailing).
- Empty states teach: "Add your first login, or import from 1Password or Bitwarden." with both buttons.
- Mac and iPad: three-column layout (sidebar: vaults, categories, tags, Watchtower, Inbox; list; detail). Keyboard: ⌘F search, ↑↓ move, ⌘C copies password of the selected item, ⌘⇧C username, ⌘N new item, ⌘E edit.

### Item detail

- Title with monogram, vault name and kind.
- Fields as rows: label (muted) above value. Concealed values show as dots with a reveal (eye) button and a copy button; *Large type* view for passwords and Secret Keys (one character per box, alternating tint for digits and symbols). Monospace for secrets.
- One-time code with a countdown ring, copy on tap; the next code previewed in the last 5 seconds.
- URLs open in the browser; usernames and passwords copy on tap.
- Copied secrets clear from the clipboard after 90 seconds and are marked as sensitive/concealed on platforms that support it (iOS `UIPasteboard` local-only with expiry, Android `ClipDescription.EXTRA_IS_SENSITIVE`).
- Watchtower notes inline ("This password is reused in 3 other items. Change it").
- Footer: attachments (open/share/save), password history, earlier versions (restore), created/updated dates.
- Actions: Edit, Favorite, Share (to a person, or a link), Move to vault, Archive, Delete (with undo toast rather than a confirmation dialog).

### Add / edit

- New item starts with a kind picker (grid of icons: Login, Password, Secure Note, Card, Identity, Document, SSH Key, API Credential, Bank Account, Database, Server, Wi-Fi, Passport, Driver License, Membership, Crypto Wallet, more…). Login is preselected; typing a title right away creates a login.
- Each kind has sensible built-in fields (see PARITY.md for 1Password's lists); *Add field* offers the typed fields; sections can be added and reordered.
- The password field has the generator inline: a refresh button and a disclosure with length / words / PIN, symbols and digits toggles, and the strength meter. Generated passwords are on by default for new logins.
- One-time code: paste an `otpauth://` link, type a secret, or scan a QR code (camera on phones, screen region on Mac).
- Save is always visible; unsaved changes prompt on dismiss.

### Vaults and sharing

- Vault list shows name, icon, item count, member avatars and your role.
- **Share vault** sheet: find people by username (on invite-only servers, also browse everyone), pick a role (*Can view*, *Can edit*, *Can manage*), optional expiry. Members list shows each person's role, expiry and a verified badge or a *Verify* button.
- **Verify** screen: both people's fingerprints in large monospace plus a QR to scan; scanning the other person's QR marks them verified. Copy explains why in one sentence ("This makes sure your server can't swap their key for its own.").
- Removing someone explains that the vault key will be replaced and runs it with a progress indicator.
- **Share item** sheet: *Send to a person* (search, sealed to their key, optional expiry) or *Create a link* (expiry 1 hour – 30 days, *Only one view* toggle), then the system share sheet. Links show "Anyone with this link can see this item until it expires."

### Inbox

Shared items and agents' access requests, newest first. An item shows who sent it (verified badge) with *Save to vault* and *Dismiss*. A request shows the agent, its owner (you), the text, and actions *Give access to a vault…*, *Send an item…*, *Dismiss*. Badge count on the Inbox entry and the app icon.

### Agents

A section under Settings (and the sidebar on desktop): list of your agents with their vault access, expiry, last activity (from the audit log) and an off switch. *New agent* walks through name → vault(s) and role → expiry → shows the `ptk_…` key once with *Copy* and a short "how to use it" with the `plaintext run` and MCP snippets. The audit log per vault is a simple timeline.

### Watchtower

A summary card (counts of weak, reused, breached, unsecured, missing 2FA) and a list per finding with one-tap fixes ("Change password" opens the site and the item in edit mode with a fresh generated password). The breach check is opt-in on first use, with a sentence explaining that only 5 characters of a hash leave the device.

### Settings

Accounts (each one's username and server), Account (username, fingerprint, change password, Emergency Kit again, devices/sessions with sign-out), Security (auto-lock time, biometrics, clipboard clear time, hide on screen share), Autofill (enable instructions per platform), Import / Export, Agents, Share links (the link page address, default `getplaintext.org/s/`, for self-hosters who host their own copy), About (server version, open source link). Admins also get People (invite, disable) on the server. On open servers everyone gets *Invite someone*.

## Autofill and the browser extension

- Extension popup: 360×560, search focused, the current site's matching logins first, one-click fill, copy buttons, the generator one click away. The keyboard shortcut (Cmd/Ctrl+Shift+L) fills the best match.
- Inline: a small Plaintext icon inside login fields offers matching logins; on signup forms it offers a generated password and saves the new login after submit (with a confirm toast).
- Matching uses the eTLD+1 by default, exact host as an option per item.
- iOS/Android: the system AutoFill/Autofill UI with Plaintext's list, search and generator; passkey creation and sign-in through the system credential provider.

## Accessibility

Every control has a label (VoiceOver / TalkBack / screen readers), touch targets ≥ 44 pt, contrast ≥ 4.5:1 for text in both themes, full keyboard navigation on desktop and in the extension, Dynamic Type up to the largest accessibility sizes without truncating secrets (they wrap or open in Large type).

## Done means

An app screen is done when it matches this document in both light and dark mode at the smallest and largest supported sizes, works with VoiceOver/TalkBack, and has screenshots of each state (empty, filled, error, loading) attached to its ticket.
