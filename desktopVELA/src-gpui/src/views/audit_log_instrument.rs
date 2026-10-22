use super::*;
use crate::instrument::shell::pill;
use crate::instrument::{alpha, mono, page, tile, tokens};
#[cfg(test)]
use chrono::Utc;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ActivityKind {
    Security,
    Items,
    Sharing,
    Sync,
}
fn kind(action: &AuditAction) -> ActivityKind {
    match action {
        AuditAction::ItemAdded { .. }
        | AuditAction::ItemUpdated { .. }
        | AuditAction::ItemDeleted { .. }
        | AuditAction::CredentialReleased { .. }
        | AuditAction::PasswordGenerated { .. } => ActivityKind::Items,
        AuditAction::ShareSent { .. }
        | AuditAction::ShareReceived { .. }
        | AuditAction::ShareLinkCreated { .. }
        | AuditAction::ShareLinkRevoked { .. } => ActivityKind::Sharing,
        AuditAction::VaultSync { .. } => ActivityKind::Sync,
        _ => ActivityKind::Security,
    }
}
pub(super) fn filtered_rows(entries: &[AuditEntry], filter: Option<ActivityKind>) -> Vec<AuditRow> {
    let mut rows = Vec::new();
    let mut day = String::new();
    for (ix, entry) in entries
        .iter()
        .enumerate()
        .filter(|(_, e)| filter.is_none_or(|f| kind(&e.action) == f))
    {
        let date = entry
            .timestamp
            .with_timezone(&Local)
            .format("%A, %d %B %Y")
            .to_string();
        if date != day {
            rows.push(AuditRow::Date(date.clone().into()));
            day = date;
        }
        rows.push(AuditRow::Entry(ix));
    }
    rows
}

impl AuditLogScreen {
    pub(super) fn render_instrument(&mut self, cx: &mut Context<Self>) -> gpui::AnyElement {
        let t = tokens(cx);
        let entries = self.entries.clone();
        let all = self.entries.as_deref().map(Vec::as_slice).unwrap_or(&[]);
        let today = Local::now().date_naive();
        let today_count = all
            .iter()
            .filter(|e| e.timestamp.with_timezone(&Local).date_naive() == today)
            .count();
        let mut counts = [0usize; 14];
        for e in all {
            let age = (today - e.timestamp.with_timezone(&Local).date_naive()).num_days();
            if (0..14).contains(&age) {
                counts[13 - age as usize] += 1;
            }
        }
        let maximum = counts.iter().copied().max().unwrap_or(1).max(1);
        let mut filters = div().flex().flex_wrap().gap(px(6.));
        for (id, label, value) in [
            ("activity-all", "All", None),
            (
                "activity-security",
                "Security",
                Some(ActivityKind::Security),
            ),
            ("activity-items", "Items", Some(ActivityKind::Items)),
            ("activity-sharing", "Sharing", Some(ActivityKind::Sharing)),
            ("activity-sync", "Sync", Some(ActivityKind::Sync)),
        ] {
            filters = filters.child(
                pill(id, label, self.instrument_filter == value, &t)
                    .h(px(32.))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.instrument_filter = value;
                        let entries = this.entries.as_deref().map(Vec::as_slice).unwrap_or(&[]);
                        let rows = filtered_rows(entries, value);
                        this.list_state.reset(rows.len());
                        this.rows = Arc::new(rows);
                        cx.notify();
                    })),
            );
        }
        let rows = self.rows.clone();
        let shown = rows
            .iter()
            .filter(|r| matches!(r, AuditRow::Entry(_)))
            .count();
        let body = if self.entries.is_none() {
            div()
                .p(px(20.))
                .text_color(t.muted)
                .child(
                    self.error
                        .clone()
                        .unwrap_or_else(|| "Loading encrypted activity…".into()),
                )
                .into_any_element()
        } else if shown == 0 {
            tile(&t)
                .child("No activity in this category.")
                .into_any_element()
        } else {
            list(self.list_state.clone(), move |ix, _, _| match &rows[ix] {
                AuditRow::Date(date) => div()
                    .flex()
                    .items_center()
                    .gap(px(12.))
                    .pt(px(18.))
                    .pb(px(10.))
                    .child(mono(date.clone(), t.faint))
                    .child(div().h(px(1.)).flex_1().bg(t.line))
                    .into_any_element(),
                AuditRow::Entry(index) => {
                    let e = &entries.as_ref().expect("loaded log")[*index];
                    let (label, _) = action_label_icon(&e.action);
                    let color = if matches!(
                        e.action,
                        AuditAction::DeviceRevoked { .. }
                            | AuditAction::ItemDeleted { .. }
                            | AuditAction::PlaintextIdentityKeysMigrated
                    ) {
                        t.risk
                    } else {
                        match kind(&e.action) {
                            ActivityKind::Security => t.signal,
                            ActivityKind::Items => t.violet,
                            ActivityKind::Sharing => t.warn,
                            ActivityKind::Sync => t.muted,
                        }
                    };
                    div()
                        .flex()
                        .items_start()
                        .gap(px(12.))
                        .py(px(10.))
                        .border_b_1()
                        .border_color(t.line)
                        .child(
                            div().w(px(44.)).pt(px(3.)).child(mono(
                                e.timestamp
                                    .with_timezone(&Local)
                                    .format("%H:%M")
                                    .to_string(),
                                t.muted,
                            )),
                        )
                        .child(div().size(px(8.)).mt(px(5.)).rounded(px(2.)).bg(color))
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .child(div().text_size(px(14.)).text_color(t.text).child(label))
                                .when_some(action_details(&e.action), |el, details| {
                                    el.child(
                                        div().text_size(px(12.)).text_color(t.muted).child(details),
                                    )
                                })
                                .child(
                                    div()
                                        .text_size(px(11.))
                                        .text_color(t.faint)
                                        .mt(px(3.))
                                        .child(device_name(e).to_string()),
                                ),
                        )
                        .into_any_element()
                }
            })
            .flex_1()
            .min_h_0()
            .w_full()
            .into_any_element()
        };
        div()
            .id("instrument-activity")
            .debug_selector(|| "instrument-activity".into())
            .size_full()
            .flex()
            .flex_col()
            .gap(px(16.))
            .p(px(20.))
            .bg(t.bg)
            .text_color(t.text)
            .child(page::heading(
                "This device / Activity",
                "Activity",
                "Every unlock, change and share on this account, newest first.",
                &t,
            ))
            .child(
                div()
                    .flex()
                    .gap(px(10.))
                    .flex_shrink_0()
                    .child(page::metric("Events", all.len(), &t))
                    .child(page::metric("Today", today_count, &t))
                    .child(
                        tile(&t)
                            .flex_1()
                            .flex()
                            .flex_col()
                            .gap(px(8.))
                            .child(mono("14 days", t.muted))
                            .child(div().h(px(30.)).flex().items_end().gap(px(4.)).children(
                                counts.into_iter().map(move |n| {
                                    div()
                                        .flex_1()
                                        .h(px(3. + 27. * n as f32 / maximum as f32))
                                        .rounded(px(2.))
                                        .bg(if n == 0 {
                                            alpha(t.violet, 0.1)
                                        } else {
                                            t.violet
                                        })
                                }),
                            )),
                    ),
            )
            .child(filters)
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .flex()
                    .flex_col()
                    .px(px(16.))
                    .pb(px(8.))
                    .rounded(px(22.))
                    .bg(t.panel)
                    .border_1()
                    .border_color(t.line)
                    .child(body),
            )
            .into_any_element()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filtering_keeps_original_indexes_and_only_relevant_day_headers() {
        use vela_desktop_core::audit::AuditSubject;
        let now = Utc::now();
        let entries = vec![
            AuditAction::VaultUnlocked,
            AuditAction::ItemAdded {
                item_type: "login".into(),
            },
            AuditAction::VaultSync { chunk_count: 1 },
        ]
        .into_iter()
        .enumerate()
        .map(|(i, action)| AuditEntry {
            id: i.to_string(),
            timestamp: now - chrono::Duration::days(i as i64),
            action,
            subject: AuditSubject::Device {
                device_name: "Test".into(),
            },
        })
        .collect::<Vec<_>>();
        let rows = filtered_rows(&entries, Some(ActivityKind::Items));
        assert_eq!(rows.len(), 2);
        assert!(matches!(rows[0], AuditRow::Date(_)));
        assert!(matches!(rows[1], AuditRow::Entry(1)));
        assert!(filtered_rows(&entries, Some(ActivityKind::Sharing)).is_empty());
    }
}
