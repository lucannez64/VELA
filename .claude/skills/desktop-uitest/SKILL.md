---
name: desktop-uitest
description: Launch, drive and record VELA's two desktop front ends (gpui and Tauri+React) headlessly. Use when asked to run, start, screenshot or UI-test the desktop app, or to verify a change in the real app rather than in tests.
---

# Running the VELA desktop apps

`desktopVELA/scripts/uitest.sh` launches either front end on a private
headless X display, drives a full journey through it with `xdotool`, and
optionally records a captioned video.

```bash
cd desktopVELA
./scripts/uitest.sh gpui              # one front end
./scripts/uitest.sh both --record     # both, into one mp4
KEEP=1 ./scripts/uitest.sh tauri      # leave :99 up to poke at it yourself
```

Output lands in `$OUT` (default `/tmp/vela-uitest`): `shots/` for
screenshots, `video/` for recordings, `run-<app>.log` for app stderr.

**Look at the screenshots.** A black frame means the app never rendered,
which the exit code will not tell you.

## The things that are not obvious

**Never run it against your real vault.** The store path comes from
`ProjectDirs::from("com","vela","VELA")`, so a dev build opens
`~/.local/share/VELA` — the same vault the installed app uses, and setup
will overwrite it without asking. The script always sets `XDG_DATA_HOME` to
a throwaway directory. Keep it that way.

**Tauri needs `GDK_BACKEND=x11`.** With a Wayland session in the
environment, tao panics at `event_loop.rs` with "Failed to initialize gtk
backend!" and the log says nothing else. It also needs
`WEBKIT_DISABLE_COMPOSITING_MODE=1`, `WEBKIT_DISABLE_DMABUF_RENDERER=1` and
`LIBGL_ALWAYS_SOFTWARE=1` to render without a GPU. gpui needs none of this —
it falls back to llvmpipe on its own (it logs a Vulkan/DRI3 complaint first,
which is noise, not failure).

**A window manager is required.** Under bare Xvfb, GTK and WebKit windows
never take keyboard focus, so `xdotool type` silently goes nowhere. The
script starts `i3` with a throwaway config.

**Both crates build a binary called `vela-desktop`**, so they overwrite each
other in `target/debug`. Build one at a time and copy it aside — the script
does this.

**`cargo build -p vela-desktop` fails without `dist/`.**
`tauri::generate_context!` resolves `frontendDist: "../dist"` at compile
time, so the React frontend has to be built first (`npm install && npm run
build`). Do not fake it with a placeholder `index.html`: it compiles and
then runs a blank window.

**Never `pkill -f vela-`.** The pattern matches the shell running the
script and kills the run. Use pidfiles.

**Clicks are coordinates against 1600x1000.** Change `GEOM` and every
coordinate has to be re-derived: run with `KEEP=1`, screenshot with
`DISPLAY=:99 import -window root /tmp/x.png`, and read the new positions off
the image.

## What the journey covers

Create vault → master password → trusted-contact recovery (Shamir Share 3,
copy, acknowledge) → unlock → Devices, Sharing, Audit Log, Settings →
Recovery section. It exercises both front ends against the same
`vela-desktop-core`, which is the point: the Tauri layer is only
`#[tauri::command]` wrappers.

Not covered, and not coverable this way: biometrics, FIDO2 security keys,
rclone cloud backup, and sync (no server). The React wizard also gates
Continue on 2 of 3 recovery methods with no skip, so it cannot be finished
headlessly — the script restarts the app to reach the unlock screen.
