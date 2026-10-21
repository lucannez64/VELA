Run `npm run dev` from desktopVELA, then open
`http://localhost:1420/tests/ui/organization.html`.

This fixture renders the production organization panel, vault list, details and
item editor against synthetic in-memory IPC. It never reads a real vault or
contacts the sync server. Changes reset on reload. Backend persistence, merge
and activation are covered separately by Rust tests.

Verify the collection filter, then open **Manage collections…** to create a
folder or tag. Editing a folder saves its name and parent together. Select an
item in the vault to reveal **Move…** and **Tags…**; these dialogs choose their
own destination independently of collection management. Successful assignment
clears the selection.

At 390×400, scroll inside the management dialog and check that Close, Cancel
and Create remain visible. Tab stays inside the dialog and Escape closes it.
The native GPUI suite covers activation over a local HTTP fixture (success and
unsupported server), compact item selectors, and dialog controls at 360×260.

For an interactive native GPUI demo, run from `desktopVELA`:

```sh
cargo run -p vela-desktop-gpui --bin vela-desktop -- --demo
```

The demo opens unlocked with 25 synthetic items, four folders and three tags.
It uses a fresh temporary encrypted store and no account credentials. Automatic
sync, extension IPC, global shortcuts and the tray are not started. A DEMO VAULT
banner identifies the window. Edits work locally; closing removes the temporary
store and relaunching creates fresh sample data. The demo has no unlock password;
close and relaunch it if you lock the session.

Native collection navigation follows VELA's existing sidebar: folders and tags
sit beneath Vault. Use the + beside each section to create a record; select a
record and use its ellipsis to edit it. On small windows, **Folders & tags** in
the vault header opens the same navigator. Add Item inherits this folder/tag.
Bulk **Edit tags** applies several explicit tag changes together and preserves
mixed tags that were left untouched. Counts reflect the selected folder/tag;
health cards appear in All items. The demo uses type icons without fetching
favicons and has a 24-hour idle timeout for UI testing.

Shared native controls live in `src-gpui/src/ui.rs`. The existing Add Item
editor and richer fields use the same `text_field`, `labeled_field` and action
buttons; collection selectors use the same field metrics. Settings and rich
sections share `section_heading`; Sidebar and collection rows share
`navigation_row`. Read-only rich values call ItemDetail's established
`field_card_inner`, including its reveal/copy actions. Custom booleans reuse
the existing sign-in toggle row. Secret fields retain the mono face when
revealed. Native tests cover duplicate-label reveal isolation in all four
VELA themes, selection menus and narrow modal layouts.
