# How VELA keeps your data safe

A plain-language guide for VELA users. It explains what VELA protects, what
it does not, and what is left to you. It is written for people who are not
security experts. Where VELA has a weak spot or an unfinished feature, this
guide says so.

This guide was checked against the source code at commit `be1f3740`
(2026-11-25). Where the design documents and the code disagree, it describes
what the code does. The disagreements are listed at the end, in
[Doc drift](#doc-drift-for-maintainers).

A short one-screen version for the privacy page is in
[`PRIVACY_SUMMARY.md`](PRIVACY_SUMMARY.md).

---

## Contents

1. [VELA in one minute](#1-vela-in-one-minute)
2. [Words used in this guide](#2-words-used-in-this-guide)
3. [What VELA protects you from, and what it doesn't](#3-what-vela-protects-you-from-and-what-it-doesnt)
4. [What the server can and can't see](#4-what-the-server-can-and-cant-see)
5. [Other companies VELA talks to](#5-other-companies-vela-talks-to)
6. [Your devices: unlocking, adding, removing](#6-your-devices-unlocking-adding-removing)
7. [Losing things, and how recovery works](#7-losing-things-and-how-recovery-works)
8. [Rotating your keys](#8-rotating-your-keys)
9. [Sync](#9-sync)
10. [The browser extension and autofill](#10-the-browser-extension-and-autofill)
11. [Passkeys](#11-passkeys)
12. [Authenticator codes (TOTP)](#12-authenticator-codes-totp)
13. [Sharing](#13-sharing)
14. [Temporary web access](#14-temporary-web-access)
15. [What the formal verification guarantees](#15-what-the-formal-verification-guarantees)
16. [What you still have to do](#16-what-you-still-have-to-do)
17. [Doc drift (for maintainers)](#doc-drift-for-maintainers)

---

## 1. VELA in one minute

When you create a VELA account, your first device makes a random secret
called the **seed**. Every key VELA uses is computed from that seed. The seed
stays on your devices. It is never sent to the VELA server.

Your vault (passwords, cards, notes, passkeys, authenticator secrets) is
encrypted on your device before it leaves. The server stores only encrypted
data. It can't open it.

There is no account password on the server. Each device has its own key pair
and proves who it is by signing a one-time challenge from the server.

```text
  Your phone          Your laptop                       VELA server
 ┌───────────┐       ┌───────────┐                    ┌──────────────┐
 │ seed      │       │ seed      │   encrypted vault  │ encrypted    │
 │ vault     │◄─────►│ vault     │◄──────────────────►│ vault blobs  │
 │ device key│       │ device key│   signed logins    │ device public│
 └───────────┘       └───────────┘                    │ keys         │
       ▲                   ▲                          │ metadata     │
       │   the seed moves only between your devices,  └──────────────┘
       └── sealed so only the receiving device can open it
```

VELA uses well-known encryption (XChaCha20-Poly1305 for your data). For
device logins and for sending keys between devices, it pairs a newer
algorithm designed to resist future quantum computers (ML-KEM-1024,
ML-DSA-87) with an older, widely studied one (X25519, Ed25519). An attacker
would have to break both. That is a design goal. It is proven only in
simplified models (see [section 15](#15-what-the-formal-verification-guarantees)).

---

## 2. Words used in this guide

| Word | Meaning |
|---|---|
| **Seed** | The 32-byte secret behind your whole vault. The spec calls it the Root Master Seed (RMS). Whoever has it can decrypt your vault. |
| **Device** | A phone, computer or tablet you have added to your account. Each has its own key pair. |
| **Server** | The VELA sync server. It stores encrypted data and checks device logins. It may be the project's server or one you run yourself. |
| **Recovery piece** | One of three pieces the seed is split into for recovery (Shamir secret sharing). Any two pieces rebuild the seed. One piece alone reveals nothing. |
| **Security key** | A physical key (YubiKey, Titan Key, etc.) or passkey registered for recovery. |
| **Epoch** | A counter that goes up each time you rotate your keys. |
| **Audit log** | An encrypted activity log (device changes, syncs, shares, fills). Only your devices can read it. |

---

## 3. What VELA protects you from, and what it doesn't

| Situation | Are you protected? | Details |
|---|---|---|
| Someone steals the server's database | **Your vault contents, yes.** Your metadata, no. | They get encrypted blobs, device public keys, one recovery piece and the metadata in [section 4](#4-what-the-server-can-and-cant-see). They can't decrypt your vault with that. **But** if they also get into your cloud storage account (which holds a second recovery piece), they can rebuild your seed. |
| The server operator turns hostile | **Vault contents, yes.** Availability, no. | A hostile operator can't read your vault. They can see metadata, refuse service, or delete your data. Your apps refuse to accept an older version of a vault piece they have already seen. A hostile operator who also has your cloud recovery piece can rebuild your seed (see [section 7](#7-losing-things-and-how-recovery-works)). |
| Someone watches your network | **Yes.** | Traffic uses TLS, and the vault is encrypted on top of that. An observer can see that you talk to the server, when, and how much. |
| Someone steals your **locked** phone | **Yes.** | On Android and iOS, the seed is locked by the phone's secure hardware and released only after a strong biometric check (or your VELA password, if you set one). |
| Someone steals your **locked** laptop | **Mostly.** | The vault file on disk is encrypted. See [section 6](#6-your-devices-unlocking-adding-removing) for how each system stores the key. Revoke the device from another one. |
| Someone uses your computer while VELA is **unlocked** | **No.** | An unlocked vault is open. Auto-lock (15 minutes by default on desktop) limits the window. Lock VELA when you step away. |
| Malware or a keylogger on your device | **No.** | This is out of scope for VELA, as for every password manager. VELA limits silent mass theft through the browser bridge (25 sites per unlock, each one logged and shown), but malware can still take what it can reach. |
| A fake website (phishing) | **Partly.** | Autofill matches the site's domain. The extension warns about look-alike addresses. Passkeys only sign for the exact site they belong to. You can still type a password into a fake site by hand. |
| Someone gets into your cloud account (iCloud, Google Drive, or your rclone storage) | **Yes, on its own.** | It holds one recovery piece. One piece reveals nothing. Combined with your security key, or with the server's piece, it rebuilds your seed. |
| Your trusted contact turns against you | **Yes, on its own.** | Their piece is sealed to them and useless alone. |
| Someone forces you to unlock or hand over a recovery piece | **No.** | VELA has no protection against coercion. |
| Someone records traffic today to decrypt it with a future quantum computer | **Designed for it.** | The key exchange and device signatures pair a post-quantum algorithm with a classical one. |
| You forget your password or lose devices | **Depends on your setup.** | See [section 7](#7-losing-things-and-how-recovery-works). VELA can't reset your password or rebuild your seed for you. |

VELA's own design documents list these as **out of scope**: malware on your
device, attacks that measure timing or power on your device, network
denial-of-service, coercion, and reading memory from a running unlocked
device (`SPEC.md` §9, `SECURITY.md`).

---

## 4. What the server can and can't see

### The server can't see

- Your seed, or any key computed from it.
- Your device private keys.
- The contents of your vault: names, usernames, passwords, URLs, notes,
  cards, identities, passkeys, authenticator secrets, folders, tags.
- Your encrypted audit log.
- Items you share with other VELA users. The server passes them along sealed.
- One-off share links. The key travels after the `#` in the link, which
  browsers never send to the server.

### The server can see (metadata)

| What | Example |
|---|---|
| Your account ID | A random ID. VELA does not ask for your email, name or phone number. |
| Your devices | How many; their names (on desktop, the computer's hostname, such as `alices-thinkpad`); their type (desktop, phone, web); when each was added, last active, or revoked; which device added which. |
| Roughly how big your vault is | The vault is split into pieces of about 1 MB. The last piece is not padded, so the server can estimate the total size to within a few dozen bytes. It can't tell what kind of items they are. A bigger vault usually means more items. |
| When you sync | Which device saved a change, and when. Open apps also keep a live connection to the server. |
| Your IP address | On every request. Rate limits keep short-lived counters keyed on IP addresses. |
| Your recovery setup | Whether recovery is set up, the public part of your recovery security key, and its server recovery piece. |
| Who you share with | For items shared with other VELA users: your account ID, theirs, when, how big, and whether a share was revoked. |
| Your share links | How many you have, when each expires, how many views are allowed and used, and whether it has a passphrase. |
| Temporary web sessions | When one is started, approved, used and ended, and which mode (read-only or read-write). |
| Key rotations | When your account rotated keys, and the epoch number. |

The server's logs also record account IDs next to some events, such as
"account registered" or "recovery share released".

If the server sits behind a proxy or content-delivery network, that company
sees the same metadata. The project's own server uses a Cloudflare tunnel
(`EPHEMERAL_WEB_ACCESS_DESIGN.md` §8).

> **About access-pattern hiding.** The spec describes a technique (Path
> ORAM) that would hide which part of your vault you read or write. The
> current apps don't use it. They upload the whole vault on every sync
> instead, which hides which item changed but not when or how much data you
> have.

---

## 5. Other companies VELA talks to

Your data also reaches some third parties. None of them get your vault
contents or your seed.

| Who | When | What they learn |
|---|---|---|
| Your cloud provider (iCloud, Google Drive, or the storage behind your rclone remote on desktop) | When you set up recovery | One recovery piece, stored next to your VELA account ID. Alone it reveals nothing. |
| DuckDuckGo's icon service, and the websites themselves | When an app shows site icons | The domains of the logins in your vault (for example, `bank.example`). All apps do this and there is no setting to turn it off. |
| Have I Been Pwned | Only when you run a breach check | For email checks: the email address you check. For password checks: the first 5 characters of the password's SHA-1 hash, never the password. |
| addy.io, SimpleLogin or Firefox Relay | Only if you create an email alias from the extension | Whatever that service needs to create the alias. |
| Google Password Manager | If, on Android, you save your recovery passkey there instead of on a physical key | That passkey. See [section 7](#7-losing-things-and-how-recovery-works) for why this matters. |

---

## 6. Your devices: unlocking, adding, removing

### How each device keeps the seed

| Device | Where the seed is kept | What unlocks it |
|---|---|---|
| iPhone / iPad | Keychain, tied to this device and to the current set of fingerprints or faces | Face ID or Touch ID (the device passcode is not accepted), or an optional VELA password |
| Android | Encrypted with a key in the Android Keystore that requires a strong biometric | Fingerprint or face, or an optional VELA password |
| macOS (desktop) | Keychain, with an access rule checked by the system | Touch ID, or the master password |
| Windows | TPM or Windows Credential Manager | Windows Hello, or the master password |
| Linux | TPM or your login keyring (GNOME Keyring, KWallet) | Fingerprint reader (fprintd), or the master password |
| Any desktop, password mode | A file encrypted with your master password (Argon2id, 64 MB of memory per guess) | The master password |

Two things worth knowing:

- **On Windows and Linux, the fingerprint or Hello check is done by VELA,
  not by the hardware.** The key itself sits in the TPM or your login
  keyring, where other programs running under your account can read it
  without a prompt. The code says so plainly. This matters only if
  something hostile already runs as you, which is out of scope anyway. If
  you want the key stored only under your password, choose password mode.
- **On phones, changing your fingerprints or faces locks VELA's stored key
  on purpose.** Adding a new finger or face makes the old key unusable, so
  someone who adds their own fingerprint can't open your vault. Before you
  change biometrics, make sure you have another way in: a VELA password on
  that phone, another device, or recovery.

### Auto-lock

The desktop app locks after 15 minutes of inactivity by default. You can set
1 minute to 24 hours. Locking wipes the decrypted vault from memory. Phones
also lock automatically; the delay is a setting.

### Adding a device

1. On the new device, choose to join an existing account. It makes its own
   key pair and shows a short code.
2. On a device you already have, open the join request. It shows four codes.
3. Pick the one that matches the new device's screen.

Picking a wrong code cancels the request. This step stops a hostile server
from swapping in its own key: the code is computed by each device from the
keys themselves. **Read the code. Don't tap the first one.**

Only then does your existing device seal the seed to the new device's key.
The server relays the sealed seed but can't open it.

### Removing (revoking) a device

Any of your devices can revoke another one from the devices list. Revoking:

- cuts the device off from the server right away, and ends its sessions;
- ends any temporary web sessions that device approved.

Revoking **does not erase** what is already on the device. The local copy
stays behind that device's lock. If you think the device was unlocked when
it was lost, or the seed may have leaked, also [rotate your keys](#8-rotating-your-keys).

Note that an attacker holding one of your unlocked devices could also revoke
your other devices.

---

## 7. Losing things, and how recovery works

### The three recovery pieces

When you set up recovery, your device splits the seed into three pieces.
**Any two rebuild the seed. One alone reveals nothing.**

```text
                         your seed
                             │
             split into 3 pieces (any 2 rebuild it)
        ┌────────────────────┼─────────────────────┐
        ▼                    ▼                     ▼
   Piece 1              Piece 2               Piece 3
   your cloud           VELA server           a trusted contact
   (iCloud, Google      released only after   (sealed so only
   Drive, or rclone     you tap your          they can open it)
   storage)             security key
```

- **Piece 1** goes to your cloud storage: iCloud key-value storage on iOS, a
  hidden app folder in Google Drive on Android, or any rclone remote on
  desktop. It is stored as-is, next to your account ID.
- **Piece 2** is stored by the server. The server releases it only after you
  prove you hold your registered recovery security key. The server keeps one
  recovery security key per account.
- **Piece 3** is meant for a trusted contact. See the status note below.

Each piece is tagged so that a tampered piece, or pieces from different
accounts or setups, fail with an error instead of producing a wrong seed.

### What recovery protects against, honestly

- **No single party can recover your account.** Not the server, not your
  cloud provider, not your contact.
- **Any two can.** This is the design, and it has a cost:
  - If someone gets into **your cloud account** and has **your security
    key**, they can recover your account.
  - The server's piece is stored as-is in its database. The security-key
    check stops the server from *handing it out* to someone else. It does
    not stop a **server operator, or someone who stole the server
    database**, from using it directly. If that person also gets into your
    cloud account, they can rebuild your seed. VELA's own assurance
    documents state this (`security/assurance/01-security-claims.md`,
    COMP-4).
  - So **your cloud account is part of your vault's security.** Protect it
    with a strong password and two-factor authentication.
- **On Android, prefer a physical security key for recovery.** The system
  dialog may offer to save the recovery passkey in your Google account. If
  you accept, your Google account then holds Piece 1 *and* the key that
  releases Piece 2, so taking over that one account is enough to recover
  your vault. iOS only accepts physical security keys here.

### What works today

| Recovery route | Status in the current apps |
|---|---|
| Cloud piece + security key | **Works** on desktop, Android and iOS. This is the main route. |
| Trusted contact + cloud piece | **Not usable yet.** The server and the cryptography support it, and the desktop can seal Piece 3 to a contact's key. But no VELA app can yet create that contact key, hold the sealed piece, or send it back during recovery. On Android and iOS, Piece 3 is shown as plain text, and the recovery screens can't accept a plain-text piece. |

In practice, then: **if you lose every device, you need both your cloud
piece and your security key.** If you lose either one as well, VELA cannot
recover your vault. Nobody, including the server operator, can do it for
you.

The best protection is simple: **keep at least two devices enrolled** (for
example a phone and a laptop, or an old phone in a drawer). Losing one device
then needs no recovery at all.

### What happens when you lose…

| You lose | What happens | What to do |
|---|---|---|
| One device, others still work | Nothing is lost. | Revoke it from another device. Rotate keys if it may have been unlocked or tampered with. |
| Every device | Your vault is still on the server, encrypted. | Install VELA on a new device and recover with your cloud piece + security key. One recovery adds exactly one new device. Then add your other devices normally. |
| Your security key (devices still fine) | Nothing yet, but recovery is now broken. | Set up recovery again with a new key, from any device. |
| Access to your cloud account (devices still fine) | Nothing yet, but recovery is now broken. | Set up recovery again with a new cloud location. |
| Every device **and** your security key **or** your cloud piece | The vault can't be recovered today. | Prevent this: keep two or more devices, and keep the security key somewhere separate. |
| Your master password (password mode) | That device can't unlock. | Use another device, or recover. VELA can't reset it. |

### After recovery

The recovering device makes its own new key pair and joins your account
with a one-time grant. The grant works once and expires. Recovery is also
rate-limited, and the server answers "not available" the same way for every
failure, so it can't be used to check whether an account exists.

Deleting your VELA account removes everything from the server in one step.
It does not remove Piece 1 from your cloud storage. Delete that yourself.

---

## 8. Rotating your keys

The desktop app has a **Rotate keys** action. It makes a new seed,
re-encrypts the whole vault under it, and sends the new seed to each of your
devices, sealed to that device.

After a rotation:

- copies of your encrypted vault taken before the rotation can't be read
  with the new keys;
- old recovery pieces stop working, including any held by a contact, and you
  must **set up recovery again** (the app tells you);
- temporary web sessions approved before the rotation stop working for new
  data.

What rotation does **not** do:

- It can't un-leak anything. Someone who already has your old seed *and* an
  old copy of your vault can still read that old copy.
- It does not replace device key pairs. A stolen device is handled by
  revoking it.

**Current limits:**

- Rotation is only in the desktop app.
- It is refused while any active device hasn't confirmed it can take part.
  Today's Android and iOS apps never send that confirmation. **So if a phone
  is enrolled, you can't rotate keys.** To rotate, you'd have to revoke the
  phones first and add them back afterwards.

If a rotation is interrupted (crash, lost network), the server rolls it back
after 15 minutes, or the next sync finishes it. Your vault is never left
half-converted.

---

## 9. Sync

- Each device keeps a full encrypted copy of your vault and works offline.
- When you save a change, the app encrypts the whole vault and uploads it in
  pieces of about 1 MB. Each piece is tied to its name, version and key
  epoch, so the server can't swap pieces around without the app noticing.
- Your apps remember the latest version of each piece they've seen. If the
  server sends an older one, they refuse it and stop instead of going back.
  (The web vault remembers only for the life of the browser tab.)
- If two devices change the same item, the desktop app keeps both versions
  and asks you to choose.
- If a piece can't be decrypted, sync stops without overwriting anything on
  the server.

What sync does not protect against: a hostile server can refuse to store
your changes, delete your data, or show different devices different
versions. VELA does not claim to prevent that. Keep more than one device.

---

## 10. The browser extension and autofill

The browser extension never holds your seed or your vault. It needs the
desktop app running and unlocked. It talks to the app through the browser's
"native messaging" channel, never over the network.

```text
  web page ──► extension ──► VELA helper ──► VELA desktop app
                             (started by      (checks the helper was
                              the browser)     started by your browser,
                                               running as you)
```

When you fill a password:

- The desktop app checks that the request comes from the VELA helper started
  by your browser, under your user account.
- It checks the vault is unlocked and not idle.
- It returns only the logins for that site's domain.
- **There is no prompt for each fill.** The developers chose this on purpose:
  a prompt that can't say who is asking trains people to click "yes". Instead:
  - one unlock can fill passwords for **at most 25 different sites**; after
    that you must lock and unlock again;
  - every fill is written to your encrypted audit log, with the site and the
    program that asked;
  - every fill shows a notice in the desktop app naming the site, such as
    "Filled example.com for …".

**If you see a fill notice you didn't cause, lock VELA and check your
computer.**

Some actions **do** ask you every time, because they log you in somewhere
rather than just filling a field:

- signing in with a passkey;
- letting the desktop app sign in to a site for you ("in-core login").

Where there is no fingerprint reader or Windows Hello, that prompt is a
dialog box. On some Linux setups (where your account can create virtual
keyboards through `/dev/uinput`), malware running as you could click that
dialog itself. A fingerprint reader is the stronger option.

The extension also:

- warns when a site's address mixes alphabets to imitate another site;
- receives a one-time code, never your authenticator secret (see
  [section 12](#12-authenticator-codes-totp)).

Like any autofill extension, it runs a script on the web pages you visit so
it can find login forms. That script never holds your vault.

The spec mentions a browser-only mode with a PIN for computers without the
desktop app. It does not exist in the current extension.

---

## 11. Passkeys

VELA can store passkeys in your vault.

- The passkey's private key **never leaves the VELA core**. Not to the
  browser, not to the web page, not to the extension.
- When a site asks you to sign in, VELA signs that one request, for that
  exact site, and sends back only the signature.
- On desktop, each sign-in needs your approval (fingerprint, Hello, Touch ID,
  or a confirmation dialog). One approval allows one signature.
- On Android, VELA can act as a passkey provider for the system.
- Passkeys sync to your other devices inside your encrypted vault, like
  everything else.

---

## 12. Authenticator codes (TOTP)

You can store a site's authenticator secret (the "TOTP" behind 6-digit
codes) in a login item. VELA then shows the codes, and the extension can
fill them.

- The extension receives the **current code**, not the secret.
- Trade-off: your password and your second factor now live in the same
  vault. Anyone who can open your vault gets both. For your most important
  accounts (your email, your cloud account, VELA's own recovery), consider
  keeping the second factor somewhere else, such as a hardware key or a
  separate authenticator app.

---

## 13. Sharing

### Sharing an item with another VELA user

- You pick one item and the recipient's account ID. VELA seals the item to
  the recipient's sharing key and signs it with your device key.
- The server delivers it but can't open it. It does see who shared with
  whom, when, and how big the item was.
- The recipient accepts or declines. An accepted copy is read-only on their
  side.
- When you edit the item, recipients using the desktop app get the update.
  Their app only accepts updates from the same sender, for the same item,
  newer than the last one.
- **Revoking stops future updates. It does not delete the copy the person
  already accepted.** Once someone has seen a password, change it if you no
  longer trust them.
- **First contact needs your confirmation.** The first time you share with
  someone, your app trusts the sharing key the server gives it. A hostile
  server could hand over its own key at that moment. If the item matters,
  confirm with the person through another channel that they received it.

### One-off share links (for people without VELA)

- VELA encrypts the item with a random key and uploads only the encrypted
  copy. The key goes in the part of the link after `#`. Browsers don't send
  that part to the server.
- **Anyone with the full link can open it** until it expires or runs out of
  views. If you paste the link into a chat app, that app has it too.
- Links always expire, from 5 minutes to 30 days. You can also limit views,
  make a link view-once, or add a passphrase. With a passphrase, the link
  alone is not enough. Send the passphrase through a different channel.
- You can revoke a link at any time. The server answers "not found" the same
  way for missing, expired, revoked and used-up links.

---

## 14. Temporary web access

You can open your vault in a browser on a computer where VELA isn't
installed, without adding that computer as a device. You approve it from one
of your devices by scanning a code.

| | Read-only (default) | Read and write (behind "Advanced — I trust this device") |
|---|---|---|
| What the browser gets | A decrypted copy of your vault, sealed to that browser | Keys for your vault's data, not your seed |
| Can it edit? | No | Yes, and changes sync |
| Default / maximum time | 30 minutes / 24 hours | 30 minutes / 24 hours |
| What revoking does | Nothing left to cut once delivered (the copy is a snapshot) | Stops access right away |
| What can't be undone | Anything already shown or copied | A browser that copied the keys keeps them until you [rotate keys](#8-rotating-your-keys) |

In both modes the browser never gets your seed, your device keys, or your
recovery pieces. Keys and data stay in the tab's memory, never in browser
storage.

Before you approve, check the request on your device: mode and duration.
Only the account ID typed into the browser can approve it, and only that
browser can collect what you approve.

**On a shared or borrowed computer:**

- Use read-only unless you really need to edit.
- **Click "End" and close the tab when you're done.** The read-only page
  shows "until" a time, but the code does not clear the page at that time,
  and it does not clear it when you switch tabs. Your vault stays on screen
  until you click End, close the tab or reload.
- Read-write tabs clear themselves when hidden, and stop working at expiry.

---

## 15. What the formal verification guarantees

### What "formal verification" means here

The VELA team wrote mathematical models of parts of the system and ran
programs (Tamarin, ProVerif, CryptoVerif) that check a property holds in
*every* possible run of the model. In those models, an attacker controls the
network and can replay, change or invent messages. A separate set of tools
(hax and F\*) checks that some small decision functions in the Rust code
match their written rules.

A proof says: "in this model, under these assumptions, this can't happen." It
is strong evidence about the design. It is not a proof that the app you
installed is free of bugs.

### What is checked (examples in plain words)

- **Adding a device:** if you pick the matching code, a server that swaps in
  its own key doesn't get your seed. One approval adds at most one device.
- **Recovery:** no single party (server, cloud, contact) can recover alone,
  and any two can. A recovery grant adds at most one device. Pieces from
  different accounts or setups can't be mixed.
- **Key rotation:** a rotation completes only when every piece of data and
  every device is covered. A sealed new seed can't be replayed or relabelled.
  Old recovery pieces and web sessions stop working.
- **Temporary web sessions:** a web session can't reach account-level actions
  (recovery, adding devices, deleting the account), and stops at expiry or
  revocation.
- **Passkeys and autofill:** a passkey private key never leaves the core; one
  approval gives one signature, for one site. A password is released only to
  an approved request, once.
- **Logins:** a login challenge works once, for its one purpose.
- **Sharing:** after the first contact, an update must come from the same
  sender, for the same item, with a higher revision number.

As recorded in `security/assurance/README.md`: 37 Tamarin theories with 302
lemmas (297 proven, plus 5 deliberate counter-examples showing that rejected
designs fail), three ProVerif models, nine CryptoVerif proofs, and 256
selected Rust functions checked with hax/F\*.

### What it does **not** cover

- **There is no proof that the whole system keeps your vault secret from a
  hostile server.** That is argued from the design: no message carries your
  seed or vault unencrypted. Many models assume the server follows its own
  rules.
- **Most of the code is tested, not proven.** Only selected small decision
  functions are checked against their rules. The user interface, storage,
  networking, the Android (Kotlin) and iOS (Swift) code, and the glue between
  them are covered by tests and audits.
- **The encryption libraries are trusted,** not proven. So are the operating
  system, the secure hardware, and the proof tools themselves.
- **The rules themselves could be wrong.** The tools prove the code matches
  the written rule, not that the rule is what was intended.
- **Not modelled at all:** malware on your device, timing attacks, server
  availability, a server showing different devices different data, the
  25-site autofill cap, share links, the audit log, breach checks, importers.
- **The access-pattern proofs (ORAM) cover a technique the apps don't
  currently use** (see [section 4](#4-what-the-server-can-and-cant-see)).
- **No independent review yet.** The audits (`SECURITY_AUDIT.md`,
  `SECURITY_REDTEAM.md`) were done by the project on its own code. iOS was
  outside the audit's scope. No outside party has reviewed the proofs.

The full list of gaps is in `security/assurance/05-known-limitations.md`.

---

## 16. What you still have to do

VELA can't do these for you.

**Before you need recovery**

- [ ] Keep **at least two devices** in your account.
- [ ] **Set up recovery** as soon as you start: the cloud piece and a
      security key. Then test that you know where both are.
- [ ] Keep the security key **away from your devices** (not on the same key
      ring as your laptop bag). On Android, choose a physical security key
      rather than saving the passkey to your Google account.
- [ ] Protect your **cloud account** (iCloud, Google, or your rclone storage)
      with a strong password and two-factor authentication. It holds a
      recovery piece.

**Every day**

- [ ] Use a **strong, unique master password** if you use password mode.
      Nobody can reset it.
- [ ] **Lock VELA** when you step away. Keep auto-lock short.
- [ ] Keep your **system and apps updated**, and don't install software you
      don't trust. VELA can't protect a computer that is already infected.
- [ ] Watch for **fill notices** you didn't cause.

**When something changes**

- [ ] **Adding a device:** read the code on the new device and pick it on
      the old one. Don't guess.
- [ ] **Changing fingerprints or faces on a phone:** make sure you have
      another way into VELA first.
- [ ] **Losing a device:** revoke it from another device. If it may have been
      unlocked, rotate your keys (desktop, see the limits in
      [section 8](#8-rotating-your-keys)), then set up recovery again.
- [ ] **Sharing for the first time:** confirm with the person through another
      channel.
- [ ] **Using a borrowed computer:** use read-only, click End, close the tab.
- [ ] **Deleting your account:** also delete the recovery file from your
      cloud storage.

**If you run your own server**

- [ ] Put it behind HTTPS, keep it updated, and back it up. Its database holds
      one recovery piece for each account and all the metadata in
      [section 4](#4-what-the-server-can-and-cant-see). Treat a database leak
      as serious, even though vaults stay encrypted.

---

## Doc drift (for maintainers)

Places where the design documents disagree with the code at `be1f3740`. The
guide above follows the code. Each item names the doc, then what the code
does.

### Recovery

1. **Recovery pieces are not encrypted.** `SPEC.md` §4.3 (line 141) says
   Share 1 is "encrypted and backed up"; line 142 says Share 2 is stored "as
   ciphertext generated client-side" and "the server … never sees Share 2
   plaintext". `libVELA/vela-crypto/src/shamir.rs:5` says Share 2 is
   "encrypted under FIDO2-bound key". In code, Share 2 is uploaded as
   `B64.encode(&share2)` (`desktopVELA/vela-desktop-core/src/recovery.rs:389`)
   and stored in `users.recovery_share`. Share 1 is a JSON envelope with a raw
   `share_b64` field on every platform (`recovery.rs` `parse_cloud_backup_envelope`,
   `iosVELA/Shared/CloudRecoveryBackup.swift`,
   `androidVELA/.../security/GoogleDriveRecoveryBackup.kt`). The shares are
   MAC-tagged (authenticated) but not encrypted. Each still reveals nothing
   alone (Shamir), so the 2-of-3 property holds; the "ciphertext" wording does
   not.
2. **The §4.3 threat note understates server + cloud collusion.** `SPEC.md`
   line 151 says an adversary with both the cloud provider and the server
   "still cannot recover by API unless they can also satisfy the user's
   WebAuthn assertion". True for the API, but the operator reads Share 2
   from the database directly. `security/assurance/01-security-claims.md`
   COMP-4 already states this non-claim; the spec should too.
3. **Trusted-contact recovery is not usable end to end.** `SPEC.md` §4.3
   (line 143) says the contact "re-seals the share to the requester's
   ephemeral key; raw share text never travels".
   - No client implements the contact's side: nothing generates a contact
     key pair for the user to hand over, stores a received envelope, or calls
     `seal_contact_share_response`. The only binding is an unused FFI export
     in `libVELA/vela-apple-bridge/src/lib.rs:690`.
   - Android (`RecoverySetupScreen.kt:52`, `:199`) and iOS
     (`AccountView.swift:150`) display raw Share 3 as text. The verified
     reconstruction policy rejects unbound contact shares
     (`libVELA/vela-crypto/src/recovery.rs` `reconstruct_account_recovery`),
     so no recovery screen can use it.
   - The Tauri recovery modal tells users "Their VELA app opens the
     envelope" (`desktopVELA/src/components/RecoverAccountModal.tsx:308`);
     no app does. The default gpui desktop has no contact recovery path at
     all (`desktopVELA/src-gpui/src/views/welcome.rs` calls only
     `complete_account_recovery`).
4. **`send_recovery_invite` sends nothing** and stores the contact's email
   in plaintext `recovery_invites.json`, and logs it at info level
   (`recovery.rs:738-775`, log at `:773`). It is still registered as a Tauri
   command (`src-tauri/src/main.rs:409`).
5. **Android recovery passkey is not restricted to security keys.** The
   comment at `RecoverySetupScreen.kt:49` and `VaultSyncManager.kt:206` says
   "a physical security key". The server uses
   `start_passkey_registration` with no attachment restriction
   (`serverVELA/vela-server/src/recovery/webauthn.rs:249`), and Android passes
   the options straight to Credential Manager (`WebAuthnCeremony.kt:31`), which
   may offer a synced Google passkey. iOS restricts to security keys
   (`iosVELA/Shared/WebAuthnCeremony.swift:47`).

### Metadata and ORAM

6. **No padding.** `SPEC.md` §5.2 (line 216) says the client "pads it to
   uniform 1MB boundaries"; §1 (line 32) and §9 (line 422) say the server
   can't learn vault size or item count; `security/assurance/01-security-claims.md`
   CONF-4 relies on "1 MB padding". Every client splits the serialized vault
   at `1 MiB - 4096` bytes and seals the last piece at its real length
   (`desktopVELA/vela-desktop-core/src/sync.rs:960` `split_plaintext_chunks`,
   `webVELA/src/main.ts:574`, `VaultSyncManager.kt:1191`,
   `iosVELA/Shared/SyncEngine.swift:355`). `vela_crypto::aead::seal` adds no
   padding. The server can infer total vault size closely.
7. **Path ORAM is not used.** `SPEC.md` §5.2 (line 229) says reads and writes
   above the trivial threshold "are routed through Path ORAM". No client calls
   `/vault/oram/...`: the desktop has unused `get_oram_path` /
   `put_oram_path` in `api.rs:1584`, `:1611`; mobile and web have none. All
   clients use `/vault/chunk/{id}` with fixed, public chunk names
   (`vault-data-000000`…) and re-upload every chunk per sync (desktop logs
   "chunked trivial ORAM payload", `sync.rs:1637`). CONF-3 and the M22/M24
   evidence apply to a mechanism outside the shipped data path.
8. **The read-only web snapshot is not padded.** `EPHEMERAL_WEB_ACCESS_DESIGN.md`
   §5.2 (line 159) says it is "padded to a uniform size". The approver seals
   the JSON as-is (`desktopVELA/vela-desktop-core/src/commands/web_session.rs:168-174`).
9. **Unlisted metadata and third parties.** Not in the spec's threat model:
   desktop sends the hostname as `device_name` (`vela-desktop-core/src/commands/session.rs:22`);
   all clients fetch favicons for vault domains from
   `icons.duckduckgo.com` and the sites themselves, with no setting
   (`vela-desktop-core/src/favicon.rs:314`, `FaviconFetcher.kt:32`,
   `FaviconService.swift:45`); server logs carry `user_id` next to events.

### Extension and local unlock

10. **No per-fill approval.** `SPEC.md` §7.4 (line 347) says "Desktop prompts
    user for a biometric touch"; the root `README.md:26` says "Autofill
    secrets require an active desktop session plus biometric/user approval".
    Code: plain autofill releases on the connection gate + unlocked, non-idle
    session, bounded by the 25-domain cap, audit entry and toast
    (`vela-desktop-core/src/ipc.rs:966`). Only passkey assertions and in-core
    login prompt (`presence.rs`). This matches the decision recorded in
    `SECURITY_AUDIT.md` D-4; the spec and README were not updated.
11. **The WASM/PIN extension fallback does not exist.** `SPEC.md` §7.4
    (line 348) describes it; `extension/src` has no WASM core, Argon2id or
    IndexedDB vault code. The assurance docs (O-9) and `SECURITY.md` still
    reference it as a weaker mode.
12. **StrongBox.** `SPEC.md` §7.2 (line 336) says Android uses StrongBox. The
    key is a Keystore AES key with `AUTH_BIOMETRIC_STRONG`; StrongBox is never
    requested (`AndroidKeystoreRmsProtector.kt:48-70`).
13. **"Stored inside the Hardware Secure Enclave."** `SPEC.md` §4.1 and §9
    (trust boundary table). On Windows and Linux the RMS falls back to
    Credential Manager or the Secret Service keyring, and even the TPM seal
    has no auth policy; Hello/fprintd are app-enforced gates
    (`vela-desktop-core/src/biometric.rs`, comments in `authenticate()` for
    both platforms). Accurate in the code comments; the spec overstates it.

### Rotation

14. **Rotation is impossible with any phone enrolled.** `docs/VAULT_REKEYING_DESIGN.md`
    §10 (line 299) lists mobile capsule adoption as a follow-up, but doesn't
    state the consequence. The desktop refuses to rotate unless every active
    device is `rekey_capable` (`vela-desktop-core/src/commands/rekey.rs:272`).
    Android defines `markRekeyCapable` (`AndroidVelaApiClient.kt:236`) but
    never calls it; iOS has no equivalent; both refuse epoch changes in sync
    (`SyncEngine.swift:27`).

### Web access

15. **Read-only web view is not wiped on hide or expiry.**
    `EPHEMERAL_WEB_ACCESS_DESIGN.md` §8 (line 285) says the page wipes and
    reloads on `visibilitychange`→hidden. `webVELA/src/main.ts:107-111` only
    does so when `authed` or `chunkKeys` is set, and the RO path clears both
    via `wipeKeys()` while keeping `items` (`main.ts:629-633`). There is no
    client-side expiry timer either, so the decrypted snapshot stays in the
    DOM past "until".

### Spec internal inconsistency

16. **Share freshness rule.** `SPEC.md` §9 threat table (line 423) says
    updates apply only if "strictly newer `updated_at`" and that capsules have
    "no AAD". §5.4 (line 267) says `updated_at` is not an admission authority
    and a signed `u64` revision is. The code follows §5.4
    (`vela-desktop-core/src/sharing.rs`, pinned `revision`).
17. **Desktop is not "Rust Tauri".** `SPEC.md` §2 and §7.3 describe the
    desktop as Tauri; the default on Windows and Linux is the native gpui app,
    with Tauri as the macOS/fallback build (`README.md`).
