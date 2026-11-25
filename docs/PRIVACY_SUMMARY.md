# VELA privacy in short

**Your vault is encrypted on your device. The VELA server stores it but
can't read it.** The secret that unlocks it stays on your devices. There is
no account password on the server, and VELA doesn't ask for your email or
name.

**The server can't see:** your passwords, notes, cards, passkeys,
authenticator secrets, site names or usernames; the items you share; the
contents of share links.

**The server can see:** a random account ID; your devices (count, names such
as your computer's hostname, type, when added and last active); roughly how
big your vault is; when you sync; your IP address; who you share items with
and when; your share links' expiry and view counts; whether recovery is set
up.

**Other services involved:** your cloud storage holds one recovery piece (useless
alone). To show site icons, the apps ask DuckDuckGo and each site for its
icon, which reveals the sites in your vault. Have I Been Pwned is contacted
only when you run a breach check, and never receives your passwords.

**Recovery:** your secret is split into three pieces: your cloud storage,
the VELA server (released only with your security key), and a trusted
contact. Any two rebuild it; one alone reveals nothing. Today, recovery uses
the cloud piece plus your security key; the trusted-contact route isn't
usable in the apps yet. Someone who controls both your cloud account and
your security key, or the server's database and your cloud account, could
rebuild your secret, so protect your cloud account well.

**What VELA can't protect against:** malware on your device, someone using
your device while VELA is unlocked, being forced to hand over access, or a
server that refuses service. No one can reset your password or recover your
vault for you if you lose your devices and your recovery pieces.

**Verification:** key parts of the design are checked with formal proof
tools. The proofs cover models and selected code, not every line of the
apps, and they have not yet been reviewed by an independent party.

Full details: [SECURITY_GUIDE.md](SECURITY_GUIDE.md).
