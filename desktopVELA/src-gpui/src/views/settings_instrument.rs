//! Direction 04: one scrolling page, seven anchored sections and compact controls.
use super::*;
use crate::instrument::shell::pill;
use crate::instrument::{alpha, mono, page, tile, tokens, Tok};
use gpui::ScrollHandle;

const SECTIONS: [&str; 7] = [
    "General",
    "Security",
    "Sync",
    "Browser extension",
    "Recovery",
    "Backup & export",
    "Danger zone",
];
fn section(index: usize, t: &Tok) -> gpui::Stateful<gpui::Div> {
    tile(t)
        .id(SharedString::from(format!("settings-section-{index}")))
        .debug_selector(move || format!("settings-section-{index}"))
        .flex_shrink_0()
        .flex()
        .flex_col()
        .child(
            mono(
                format!("{:02} / {}", index + 1, SECTIONS[index]),
                if index == 6 { t.risk } else { t.muted },
            )
            .mb(px(16.)),
        )
}
fn row(
    title: &str,
    desc: impl Into<SharedString>,
    control: impl IntoElement,
    compact: bool,
    t: &Tok,
) -> gpui::Div {
    div()
        .w_full()
        .flex_shrink_0()
        .py(px(14.))
        .border_t_1()
        .border_color(t.line)
        .flex()
        .gap(px(18.))
        .when(compact, |el| el.flex_col())
        .when(!compact, |el| el.items_center())
        .child(
            div()
                .flex_1()
                .min_w_0()
                .child(
                    div()
                        .text_size(px(14.))
                        .font_weight(gpui::FontWeight::MEDIUM)
                        .child(title.to_string()),
                )
                .child(
                    div()
                        .mt(px(4.))
                        .text_size(px(12.5))
                        .line_height(px(19.))
                        .text_color(t.muted)
                        .child(desc.into()),
                ),
        )
        .child(
            div()
                .flex_shrink_0()
                .flex()
                .flex_wrap()
                .items_center()
                .gap(px(8.))
                .child(control),
        )
}
fn options(
    key: &'static str,
    opts: &[(u32, &'static str)],
    value: u32,
    t: &Tok,
    cx: &mut Context<SettingsScreen>,
) -> gpui::Div {
    let mut seg = div()
        .flex()
        .flex_wrap()
        .p(px(3.))
        .rounded_full()
        .bg(t.panel2)
        .border_1()
        .border_color(t.line);
    for &(n, label) in opts {
        seg = seg.child(
            pill(format!("setting-{key}-{n}"), label, value == n, t)
                .h(px(30.))
                .px(px(12.))
                .text_size(px(12.))
                .border_0()
                .when(value != n, |el| el.bg(alpha(t.panel, 0.)))
                .when(value == n, |el| el.bg(t.violet).text_color(t.primary_fg))
                .on_click(cx.listener(move |this, _, _, cx| {
                    if let Some(mut settings) = this.settings.clone() {
                        match key {
                            "idle" => settings.auto_lock_minutes = n,
                            "clip" => settings.clipboard_clear_seconds = n,
                            _ => settings.background_sync_minutes = n,
                        };
                        this.save(settings, cx);
                    }
                })),
        );
    }
    seg
}
fn toggle(
    id: &'static str,
    value: bool,
    t: &Tok,
    cx: &mut Context<SettingsScreen>,
) -> impl IntoElement {
    div()
        .id(id)
        .debug_selector(move || id.into())
        .w(px(46.))
        .h(px(26.))
        .rounded_full()
        .bg(if value { t.signal } else { t.panel3 })
        .border_1()
        .border_color(t.line2)
        .p(px(3.))
        .flex()
        .items_center()
        .when(value, |el| el.justify_end())
        .cursor_pointer()
        .child(
            div()
                .size(px(18.))
                .rounded_full()
                .bg(if value { t.on_signal } else { t.muted }),
        )
        .on_click(cx.listener(move |this, _, _, cx| {
            if let Some(mut settings) = this.settings.clone() {
                if id == "setting-biometric" {
                    settings.require_biometric_on_reveal = !settings.require_biometric_on_reveal;
                } else {
                    settings.sync_on_startup = !settings.sync_on_startup;
                }
                this.save(settings, cx);
            }
        }))
}
impl SettingsScreen {
    pub(super) fn render_instrument(
        &mut self,
        settings: &Settings,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let t = tokens(cx);
        let width = f32::from(window.viewport_size().width);
        let compact = width < 760.;
        let side_nav = width > 1060.;
        let scroll = window
            .use_keyed_state("reference-settings-scroll", cx, |_, _| ScrollHandle::new())
            .read(cx)
            .clone();
        let mut nav = div()
            .p(px(if side_nav { 10. } else { 5. }))
            .rounded(px(if side_nav { 22. } else { 28. }))
            .bg(t.panel)
            .border_1()
            .border_color(t.line)
            .flex()
            .flex_shrink_0()
            .gap(px(2.));
        if side_nav {
            nav = nav.flex_col().w(px(210.)).self_start();
        }
        for (index, label) in SECTIONS.iter().enumerate() {
            let scroll = scroll.clone();
            nav = nav.child(
                div()
                    .id(SharedString::from(format!("settings-jump-{index}")))
                    .debug_selector(move || format!("settings-jump-{index}"))
                    .flex_shrink_0()
                    .h(px(36.))
                    .px(px(10.))
                    .rounded(px(12.))
                    .flex()
                    .items_center()
                    .gap(px(10.))
                    .cursor_pointer()
                    .text_color(t.muted)
                    .text_size(px(13.))
                    .hover(|el| el.bg(t.panel2).text_color(t.text))
                    .child(mono(format!("{:02}", index + 1), t.faint))
                    .child(*label)
                    .on_click(cx.listener(move |_, _, _, cx| {
                        scroll.scroll_to_top_of_item(index);
                        cx.notify();
                    })),
            );
        }
        let current = ThemeId::from_setting(&settings.theme);
        let mut theme_rows = div().flex().flex_col().gap(px(10.)).py(px(16.));
        for themes in crate::instrument::THEMES.chunks(if compact { 2 } else { 4 }) {
            let mut cards = div().flex().gap(px(10.));
            for &id in themes {
                let tk = crate::instrument::tokens_for(id);
                let selected = id == current;
                cards = cards.child(
                    div()
                        .id(SharedString::from(format!("settings-theme-{id:?}")))
                        .debug_selector(move || format!("settings-theme-{id:?}"))
                        .flex_1()
                        .min_w_0()
                        .p(px(10.))
                        .rounded(px(20.))
                        .bg(t.panel2)
                        .border_1()
                        .border_color(if selected { t.violet } else { t.line2 })
                        .cursor_pointer()
                        .child(
                            div()
                                .h(px(80.))
                                .rounded(px(14.))
                                .bg(tk.bg)
                                .p(px(10.))
                                .flex()
                                .flex_col()
                                .justify_between()
                                .child(
                                    div()
                                        .child(
                                            div()
                                                .w(px(88.))
                                                .max_w_full()
                                                .h(px(5.))
                                                .rounded_full()
                                                .bg(tk.text),
                                        )
                                        .child(
                                            div()
                                                .w(px(55.))
                                                .h(px(4.))
                                                .mt(px(6.))
                                                .rounded_full()
                                                .bg(tk.muted),
                                        ),
                                )
                                .child(
                                    div()
                                        .flex()
                                        .gap(px(4.))
                                        .child(div().size(px(9.)).rounded_full().bg(tk.violet))
                                        .child(div().size(px(9.)).rounded_full().bg(tk.signal))
                                        .child(div().size(px(9.)).rounded_full().bg(tk.risk)),
                                ),
                        )
                        .child(
                            div()
                                .mt(px(10.))
                                .text_size(px(13.))
                                .child(crate::instrument::theme_name(id)),
                        )
                        .child(mono(if tk.dark { "Dark" } else { "Light" }, t.muted).mt(px(4.)))
                        .on_click(cx.listener(move |this, _, _, cx| {
                            if let Some(mut settings) = this.settings.clone() {
                                settings.theme = id.to_setting();
                                this.save(settings, cx);
                            }
                        })),
                );
            }
            theme_rows = theme_rows.child(cards);
        }
        let shortcut = if self.editing_shortcut {
            div()
                .flex()
                .flex_wrap()
                .gap(px(6.))
                .child(
                    text_input("instrument-shortcut")
                        .state(self.shortcut_state.downgrade())
                        .text_color(t.text)
                        .caret_color(t.text)
                        .bg(t.panel2)
                        .rounded(px(10.))
                        .p(px(8.))
                        .w(px(170.)),
                )
                .child(
                    pill("shortcut-save", "Save", false, &t)
                        .h(px(32.))
                        .on_click(cx.listener(|this, _, _, cx| {
                            if let Some(mut settings) = this.settings.clone() {
                                settings.quick_search_shortcut =
                                    this.shortcut_state.read(cx).as_str().trim().to_string();
                                this.save(settings, cx);
                            }
                            this.editing_shortcut = false;
                            cx.notify();
                        })),
                )
                .into_any_element()
        } else {
            div()
                .flex()
                .items_center()
                .gap(px(8.))
                .child(
                    div()
                        .font_family(fonts::MONO)
                        .text_size(px(11.))
                        .text_color(t.muted)
                        .child(settings.quick_search_shortcut.clone()),
                )
                .child(
                    pill("edit-shortcut", "Change", false, &t)
                        .h(px(32.))
                        .on_click(cx.listener(|this, _, _, cx| {
                            if let Some(settings) = &this.settings {
                                let shortcut = settings.quick_search_shortcut.clone();
                                this.shortcut_state
                                    .update(cx, |field, cx| field.emplace(&shortcut, cx));
                            }
                            this.editing_shortcut = true;
                            cx.notify();
                        })),
                )
                .into_any_element()
        };
        let general = section(0, &t)
            .child(div().text_size(px(14.)).child("Appearance"))
            .child(
                div()
                    .text_size(px(12.5))
                    .text_color(t.muted)
                    .mt(px(5.))
                    .child("Choose how VELA looks on this device."),
            )
            .child(theme_rows)
            .child(row(
                "Quick search shortcut",
                "Opens search from anywhere.",
                shortcut,
                compact,
                &t,
            ));
        let security=section(1, &t)
            .child(row("Auto-lock after idle","Locks the vault when you step away.",options("idle",&[(1,"1 min"),(5,"5 min"),(15,"15 min"),(60,"1 hour"),(1440,"1 day")],settings.auto_lock_minutes,&t,cx),compact,&t))
            .child(row("Clear clipboard","Time before copied data is cleared.",options("clip",&[(15,"15 s"),(30,"30 s"),(60,"1 min"),(0,"Never")],settings.clipboard_clear_seconds,&t,cx),compact,&t))
            .child(row("Require biometrics on reveal","Authenticate before showing passwords.",toggle("setting-biometric",settings.require_biometric_on_reveal,&t,cx),compact,&t))
            .child(row("Security key","Add a hardware check to your recovery setup.",pill("security-key-setup","Configure",false,&t).h(px(32.)).on_click(cx.listener(|this,_,_,cx|this.open_security_key_modal(cx))),compact,&t))
            .child(row("Rotate vault keys","Re-encrypts your vault with new keys. Other devices adopt them on their next sync.",pill("rotate-keys",if self.rotating{"Rotating…"}else{"Rotate"},false,&t).h(px(32.)).on_click(cx.listener(|this,_,_,cx|{if !this.rotating{this.rotate_keys(cx);}})),compact,&t))
            .when_some(self.rotate_status.clone(),|el,msg|el.child(div().text_size(px(12.)).text_color(t.muted).child(msg)));
        let mut server_controls = div()
            .flex()
            .flex_wrap()
            .gap(px(8.))
            .child(
                pill("edit-server-url", "Edit", false, &t)
                    .h(px(32.))
                    .on_click(cx.listener(|this, _, _, cx| {
                        if let Some(settings) = &this.settings {
                            let url = settings.server_url.clone();
                            this.server_url_state
                                .update(cx, |field, cx| field.emplace(&url, cx));
                        }
                        this.editing_server_url = true;
                        cx.notify();
                    })),
            )
            .child(
                pill(
                    "sync-now",
                    if self.syncing {
                        "Syncing…"
                    } else {
                        "Sync now"
                    },
                    false,
                    &t,
                )
                .h(px(32.))
                .on_click(cx.listener(|this, _, _, cx| {
                    if !this.syncing {
                        this.sync_now(cx);
                    }
                })),
            );
        if self.editing_server_url {
            server_controls = server_controls
                .child(
                    text_input("instrument-server-url")
                        .state(self.server_url_state.downgrade())
                        .w(px(190.))
                        .bg(t.panel2)
                        .text_color(t.text)
                        .caret_color(t.text)
                        .p(px(8.))
                        .rounded(px(8.)),
                )
                .child(
                    pill("save-server-url", "Save", true, &t)
                        .h(px(32.))
                        .on_click(cx.listener(|this, _, _, cx| {
                            if let Some(mut settings) = this.settings.clone() {
                                settings.server_url =
                                    this.server_url_state.read(cx).as_str().trim().to_string();
                                this.save(settings, cx);
                            }
                            this.editing_server_url = false;
                            cx.notify();
                        })),
                );
        }
        let sync = section(2, &t)
            .child(row(
                "Server",
                if settings.server_url.is_empty() {
                    "No server configured".into()
                } else {
                    settings.server_url.clone()
                },
                server_controls,
                compact,
                &t,
            ))
            .child(row(
                "Sync on startup",
                "Pull changes when the app opens.",
                toggle("setting-sync-start", settings.sync_on_startup, &t, cx),
                compact,
                &t,
            ))
            .child(row(
                "Background sync",
                "How often to sync while VELA is open.",
                options(
                    "sync",
                    &[(5, "5 min"), (15, "15 min"), (60, "1 hour")],
                    settings.background_sync_minutes,
                    &t,
                    cx,
                ),
                compact,
                &t,
            ))
            .when_some(self.sync_error.clone(), |el, error| {
                el.child(div().text_color(t.risk).text_size(px(12.)).child(error))
            })
            .when(
                self.sync_status
                    .as_ref()
                    .is_some_and(|s| !s.conflicts.is_empty()),
                |el| {
                    el.child(
                        pill("sync-conflicts", "Resolve conflicts", false, &t)
                            .on_click(cx.listener(|this, _, _, cx| this.open_conflict_modal(cx))),
                    )
                },
            );
        let extension = section(3, &t).child(row(
            if settings.extension_connected {
                "Extension connected"
            } else {
                "Extension not connected"
            },
            "Pair the VELA extension with this desktop to fill credentials.",
            crate::instrument::tag(
                if settings.extension_connected {
                    "Connected"
                } else {
                    "Not connected"
                },
                if settings.extension_connected {
                    crate::instrument::TagKind::Ok
                } else {
                    crate::instrument::TagKind::Plain
                },
                &t,
            ),
            compact,
            &t,
        ));
        #[cfg(windows)]
        let extension = extension.child(row(
            "System passkeys",
            "Use VELA for passkeys across browsers and apps.",
            {
                let mut buttons = div().flex().flex_wrap().gap(px(8.));
                for (id, label, action) in [
                    ("provider-enable", "Enable", ProviderAction::Enable),
                    ("provider-sync", "Sync passkeys", ProviderAction::Sync),
                    ("provider-disable", "Disable", ProviderAction::Disable),
                ] {
                    buttons = buttons.child(pill(id, label, false, &t).h(px(32.)).on_click(
                        cx.listener(move |this, _, _, cx| this.passkey_provider_action(action, cx)),
                    ));
                }
                buttons
            },
            compact,
            &t,
        ));
        let recovery = section(4, &t)
            .child(row(
                "Trusted contact",
                if self
                    .recovery_status
                    .as_ref()
                    .is_some_and(|s| s.trusted_contact_acknowledged)
                {
                    "Recovery share delivered."
                } else {
                    "Not configured. Give a sealed recovery share to someone you trust."
                },
                pill("recovery-trusted-contact", "Configure", false, &t)
                    .h(px(32.))
                    .on_click(cx.listener(|this, _, _, cx| this.open_trusted_contact_modal(cx))),
                compact,
                &t,
            ))
            .child(row(
                "Cloud backup",
                if self
                    .recovery_status
                    .as_ref()
                    .is_some_and(|s| s.cloud_backup_delivered)
                {
                    "Recovery share backed up."
                } else {
                    "Keep an encrypted recovery share in your cloud storage."
                },
                pill("recovery-cloud-backup", "Configure", false, &t)
                    .h(px(32.))
                    .on_click(cx.listener(|this, _, _, cx| this.open_cloud_backup_modal(cx))),
                compact,
                &t,
            ))
            .child(row(
                "Security key",
                if self
                    .recovery_status
                    .as_ref()
                    .is_some_and(|s| s.security_key_delivered)
                {
                    "A hardware recovery method is configured."
                } else {
                    "Use a hardware key as a recovery method."
                },
                pill("recovery-security-key", "Configure", false, &t)
                    .h(px(32.))
                    .on_click(cx.listener(|this, _, _, cx| this.open_security_key_modal(cx))),
                compact,
                &t,
            ))
            .when(
                self.recovery_status
                    .as_ref()
                    .is_some_and(|s| s.setup_in_progress),
                |el| {
                    el.child(
                        pill("recovery-finish", "Finish recovery setup", true, &t)
                            .mt(px(14.))
                            .on_click(cx.listener(|this, _, _, cx| this.finalize_recovery(cx))),
                    )
                },
            );
        let backup = section(5, &t)
            .child(row(
                "Encrypted backup",
                "A sealed file that only your passphrase opens.",
                pill("export-vault-encrypted", "Create backup", false, &t)
                    .h(px(32.))
                    .on_click(cx.listener(|this, _, _, cx| this.open_archive_export(cx))),
                compact,
                &t,
            ))
            .child(row(
                "Export vault",
                "Bitwarden-compatible JSON or CSV. Exports are not encrypted.",
                div()
                    .flex()
                    .gap(px(8.))
                    .child(
                        pill("export-vault", "JSON", false, &t)
                            .h(px(32.))
                            .on_click(cx.listener(|this, _, _, cx| this.export_vault(cx))),
                    )
                    .child(
                        pill("export-vault-csv", "CSV", false, &t)
                            .h(px(32.))
                            .on_click(cx.listener(|this, _, _, cx| this.export_vault_csv(cx))),
                    ),
                compact,
                &t,
            ))
            .child(row(
                "Import vault",
                "Bitwarden, 1Password (.1pif/.1pux), KeePass, Chrome/Edge/Safari or Proton Pass. Folders, tags and rich fields are preserved or reported.",
                pill("import-vault", "Import", false, &t)
                    .h(px(32.))
                    .on_click(cx.listener(|this, _, _, cx| this.import_vault(cx))),
                compact,
                &t,
            ))
            .child(row(
                "Restore backup",
                "Restore an encrypted .vela backup.",
                pill("import-vault-archive", "Restore", false, &t)
                    .h(px(32.))
                    .on_click(cx.listener(|this, _, _, cx| this.open_archive_import(cx))),
                compact,
                &t,
            ))
            .when_some(self.export_import_status.clone(), |el, msg| {
                el.child(div().text_size(px(12.)).text_color(t.muted).child(msg))
            });
        let danger = section(6, &t)
            .border_color(alpha(t.risk, 0.32))
            .child(row(
                "Sign out",
                "Locks this device and clears the current session.",
                pill("sign-out", "Sign out", false, &t)
                    .h(px(32.))
                    .on_click(cx.listener(|this, _, _, cx| this.sign_out(cx))),
                compact,
                &t,
            ))
            .child(row(
                "Delete vault",
                "Permanently delete your vault. The next step requires typing DELETE to confirm.",
                pill("delete-vault", "Delete forever", false, &t)
                    .h(px(32.))
                    .text_color(t.risk)
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.show_delete_modal = true;
                        cx.notify();
                    })),
                compact,
                &t,
            ));
        if self.category == SettingsCategory::Recovery {
            scroll.scroll_to_top_of_item(4);
            self.category = SettingsCategory::General;
        }
        let stack = div()
            .id("instrument-settings-scroll")
            .debug_selector(|| "instrument-settings-scroll".into())
            .flex_1()
            .min_w_0()
            .min_h_0()
            .overflow_y_scroll()
            .track_scroll(&scroll)
            .flex()
            .flex_col()
            .gap(px(12.))
            .children([general, security, sync, extension, recovery, backup, danger])
            .when_some(self.error.clone(), |el, error| {
                el.child(div().text_color(t.risk).text_size(px(12.)).child(error))
            });
        let mut nav = Some(nav);
        let body = div()
            .flex_1()
            .min_h_0()
            .flex()
            .gap(px(12.))
            .when(side_nav, |el| el.child(nav.take().unwrap()))
            .child(stack);
        div()
            .relative()
            .size_full()
            .flex()
            .flex_col()
            .gap(px(20.))
            .bg(t.bg)
            .text_color(t.text)
            .child(page::grid(t))
            .child(page::heading(
                "This device / Settings",
                "Settings",
                "Changes save automatically and apply to this device.",
                &t,
            ))
            .when(!side_nav, |el| {
                el.child(
                    div()
                        .id("settings-section-nav")
                        .overflow_x_scroll()
                        .flex_shrink_0()
                        .child(nav.take().unwrap()),
                )
            })
            .child(body)
            .when(self.show_delete_modal, |el| {
                el.child(delete_modal(
                    &crate::theme::current_palette(cx),
                    self,
                    window,
                    cx,
                ))
            })
            .when(self.conflict_modal.is_some(), |el| {
                el.child(conflict_resolution_modal(
                    &crate::theme::current_palette(cx),
                    self,
                    window,
                    cx,
                ))
            })
            .when(self.show_security_key_modal, |el| {
                el.child(security_key_modal(
                    &crate::theme::current_palette(cx),
                    self,
                    window,
                    cx,
                ))
            })
            .when(self.show_cloud_backup_modal, |el| {
                el.child(cloud_backup_modal(
                    &crate::theme::current_palette(cx),
                    self,
                    window,
                    cx,
                ))
            })
            .when(self.show_trusted_contact_modal, |el| {
                el.child(trusted_contact_modal(
                    &crate::theme::current_palette(cx),
                    self,
                    window,
                    cx,
                ))
            })
            .when(self.show_archive_modal, |el| {
                el.child(archive_passphrase_modal(
                    &crate::theme::current_palette(cx),
                    self,
                    window,
                    cx,
                ))
            })
            .into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modal_test_support as ui;
    use gpui::{size, Modifiers, TestAppContext};
    #[gpui::test]
    fn reference_settings_is_one_document_with_four_theme_previews_and_working_jump_links(
        cx: &mut TestAppContext,
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _guard = runtime.enter();
        let dir = tempfile::tempdir().unwrap();
        let state = ui::state(&dir);
        cx.update(|cx| {
            cx.set_global(crate::instrument::ActiveInterface(
                crate::instrument::InterfaceMode::Instrument,
            ))
        });
        let (screen, cx) = cx.add_window_view(|_, cx| {
            ui::fonts(cx);
            let mut screen = SettingsScreen::new(state, cx);
            screen.settings = Some(Settings::default());
            screen._pulse_task = Task::ready(());
            screen._extension_status_task = Task::ready(());
            screen
        });
        for width in [945., 1440., 390.] {
            cx.simulate_resize(size(px(width), px(1025.)));
            cx.run_until_parked();
            for theme in crate::instrument::THEMES {
                let key: &'static str =
                    Box::leak(format!("settings-theme-{theme:?}").into_boxed_str());
                let b = ui::bounds(cx, key);
                assert!(b.left() >= px(0.) && b.right() <= px(width));
            }
            assert!(
                ui::bounds(cx, "settings-section-1").top()
                    > ui::bounds(cx, "settings-section-0").top()
            );
        }
        cx.simulate_resize(size(px(945.), px(1025.)));
        cx.run_until_parked();
        let b = ui::bounds(cx, "settings-jump-1");
        cx.simulate_mouse_move(b.center(), None, Modifiers::default());
        cx.simulate_click(b.center(), Modifiers::default());
        cx.run_until_parked();
        assert!(
            ui::bounds(cx, "settings-section-0").top()
                < ui::bounds(cx, "instrument-settings-scroll").top()
        );
        assert!(!screen.read_with(cx, |s, _| s.show_delete_modal));
        cx.update(|_, cx| cx.set_global(crate::theme::ActiveTheme(ThemeId::Paper)));
        cx.run_until_parked();
        assert_eq!(
            screen.read_with(cx, |s, _| s.settings.as_ref().unwrap().theme.clone()),
            ThemeId::Paper.to_setting()
        );
    }
}
