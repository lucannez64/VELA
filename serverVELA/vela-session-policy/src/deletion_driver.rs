//! Pure `/account` (permanent account deletion) decision driver.
//!
//! The HTTP handler in `vela-server` performs the effectful steps: the two
//! row scans, the sled JTI/sentinel writes that lock every device and web
//! session out, the single SQL transaction, its eight `DELETE` statements and
//! the commit. This module owns every *decision* between those effects:
//!
//! 1. whether the authenticated actor may delete at all, and whether every
//!    effect is scoped to the one account its session names;
//! 2. whether a device or web-session scan succeeded or is terminal;
//! 3. that a lockout failure does not abort the deletion (it only locks out,
//!    and the rows are about to disappear) while a scan or SQL failure does;
//! 4. which table is deleted next, in the fixed historical order;
//! 5. whether the `users` delete found the account row — the existence signal
//!    — and therefore whether the transaction may commit or must roll back;
//! 6. how a transaction begin, table/`users` delete, and commit outcome are
//!    classified, and which failure is terminal.
//!
//! Effect order is part of the contract: every device and every web session is
//! locked out *before* the SQL transaction starts, the transaction commits only
//! after the `users` row was actually deleted, and any SQL failure or absent
//! account produces a terminal failure with no commit effect (the handler drops
//! the transaction, which rolls it back). `deletion_state_is_sound` and
//! `deletion_effect_is_sound` encode that order, and
//! `proofs/fstar/deletion-driver-lemmas` proves it over every event list.
//!
//! The driver is a per-request value: it does not observe the store or SQL
//! database and does not coordinate concurrent requests. Every input is an
//! observation produced by the handler. Lockout observations are accepted in
//! both forms because the historical handler ignores a store-side lockout
//! failure and proceeds to delete the rows (a failed lockout can only shorten
//! the window in which a stolen token is usable, never keep the account).

/// Actor and scope facts established by the authenticated `DeviceSession`
/// extractor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeletionActorObservation {
    /// The middleware verified the PASETO identity.
    pub authenticated: bool,
    /// The middleware's durable `devices.revoked = 0` check.
    pub device_active: bool,
    /// Every store key and SQL predicate of this request is scoped to the one
    /// account the verified session names. The shipped handler uses a single
    /// `session.user_id` for the device scan, the web-session scan, all eight
    /// deletes and the existence check, so this is true; the driver still
    /// refuses a request that is not, so a rewired caller cannot authorize an
    /// effect for a second account.
    pub scoped_to_session_account: bool,
}

/// Outcome of one row scan (devices, or web sessions).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanObservation {
    /// The query returned (possibly zero) rows.
    Rows,
    /// The query itself failed.
    QueryFailed,
}

/// Outcome of a store-side lockout batch. `StorageFailed` is an observation,
/// not proof that nothing was written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LockoutObservation {
    Applied,
    StorageFailed,
}

/// Outcome of opening the one SQL transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionObservation {
    Begun,
    Failed,
}

/// Outcome of one `DELETE` inside the transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableDeleteObservation {
    Deleted,
    Failed,
}

/// Outcome of `DELETE FROM users WHERE id = ?`. `Absent` is the zero-row
/// result and is the account-existence signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UsersDeleteObservation {
    Deleted,
    Absent,
    Failed,
}

/// Outcome of the transaction commit. `Failed` is an observation, not proof
/// that nothing was committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitObservation {
    Committed,
    Failed,
}

/// The account-scoped tables the handler deletes, in the historical order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeletionTable {
    WebSessions,
    ShareInbox,
    SharedItems,
    Sends,
    VaultChunks,
    OramBuckets,
    Devices,
}

impl DeletionTable {
    /// Zero-based position in the fixed deletion order.
    pub const fn index(self) -> u8 {
        match self {
            DeletionTable::WebSessions => 0,
            DeletionTable::ShareInbox => 1,
            DeletionTable::SharedItems => 2,
            DeletionTable::Sends => 3,
            DeletionTable::VaultChunks => 4,
            DeletionTable::OramBuckets => 5,
            DeletionTable::Devices => 6,
        }
    }
}

/// Where the deletion is in its decision sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeletionStage {
    /// The handler may scan the account's `devices` rows.
    ObserveDevices,
    /// A successful device scan: lock every scanned device out.
    LockoutDevices,
    /// The device lockout was observed: scan the account's web sessions.
    ObserveWebSessions,
    /// A successful web-session scan: lock every scanned session out.
    LockoutWebSessions,
    /// Every device and web session was locked out: open the transaction.
    BeginTransaction,
    /// A table delete was observed deleted; emit the next delete.
    DeleteTable(DeletionTable),
    /// Every table delete was observed deleted: change the existence signal.
    DeleteUsers,
    /// The `users` row was deleted: commit.
    Commit,
    /// A terminal success or failure was decided. Later events are ignored.
    Done,
}

/// One driver event. The handler feeds exactly the observation it obtained
/// from the corresponding effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeletionEvent {
    DevicesScanned(ScanObservation),
    DeviceLockout(LockoutObservation),
    WebSessionsScanned(ScanObservation),
    WebSessionLockout(LockoutObservation),
    Transaction(TransactionObservation),
    TableDeleted(TableDeleteObservation),
    UsersDeleted(UsersDeleteObservation),
    Commit(CommitObservation),
}

/// Failure categories, preserving the handler's historical status/message
/// precedence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeletionFailure {
    /// The actor was not an authenticated, active device. Terminal, no effect.
    Unauthenticated,
    /// The request was not scoped to the account its session names. Terminal,
    /// no effect.
    CrossAccount,
    /// The device scan query failed. Terminal, no effect.
    DeviceScanStorage,
    /// The web-session scan query failed. Terminal, no lockout/transaction.
    WebSessionScanStorage,
    /// The transaction could not be opened. Terminal, nothing to roll back.
    TransactionStorage,
    /// A table delete failed. Terminal; the handler drops the transaction.
    TableStorage,
    /// The `users` delete failed. Terminal; the handler drops the transaction.
    UsersStorage,
    /// The `users` row did not exist. Terminal; the handler drops the
    /// transaction and reports "account not found".
    AccountNotFound,
    /// The commit failed. Terminal; `committed` stays false (an ambiguous
    /// commit failure is not reported as a successful deletion).
    CommitStorage,
}

/// The effect the handler must perform next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeletionEffect {
    /// `SELECT id FROM devices WHERE user_id = ?`.
    ScanDevices,
    /// Revoke every tracked JTI and write the `device:revoked:` sentinel for
    /// every scanned device.
    LockoutDevices,
    /// `SELECT id FROM web_sessions WHERE user_id = ? OR approver_user_id = ?`.
    ScanWebSessions,
    /// Revoke every tracked JTI and write the `device:revoked:` sentinel for
    /// every scanned web session.
    LockoutWebSessions,
    /// Open the one SQL transaction.
    BeginTransaction,
    /// Delete every row of one table that is scoped to the account.
    DeleteTable(DeletionTable),
    /// `DELETE FROM users WHERE id = ?` — the account existence signal.
    DeleteUsers,
    /// Commit the transaction.
    CommitTransaction,
    /// Terminal success.
    Complete,
    /// Terminal failure. The handler must not commit; dropping the
    /// transaction rolls it back.
    Fail(DeletionFailure),
    /// Ignored/out-of-order event or a terminal driver.
    Idle,
}

/// Per-request driver state. Every field is a decision fact established by a
/// prior transition, never a claim about the store or SQL database.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeletionDriver {
    pub stage: DeletionStage,
    /// The actor was authenticated and its device was active when the request
    /// began.
    pub actor_active: bool,
    /// Every effect of the request is scoped to the session's own account.
    pub same_account: bool,
    /// The driver has instructed the device lockout batch.
    pub devices_locked: bool,
    /// The device lockout outcome was observed (applied or failed).
    pub devices_lockout_done: bool,
    /// The driver has instructed the web-session lockout batch.
    pub web_sessions_locked: bool,
    /// The web-session lockout outcome was observed (applied or failed).
    pub web_sessions_lockout_done: bool,
    /// The driver has instructed the transaction to be opened.
    pub transaction_open: bool,
    /// The transaction begin was observed as successful.
    pub transaction_started: bool,
    /// The `users` delete was observed as having deleted the row.
    pub users_deleted: bool,
    /// The commit was observed as successful.
    pub committed: bool,
    /// A success response was authorized.
    pub responded: bool,
    /// A terminal failure was decided.
    pub failed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeletionTransition {
    pub driver: DeletionDriver,
    pub effect: DeletionEffect,
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas. It is stronger than the individual trace properties.
pub fn deletion_state_is_sound(d: DeletionDriver) -> bool {
    let lockouts_clear = !d.devices_locked
        && !d.devices_lockout_done
        && !d.web_sessions_locked
        && !d.web_sessions_lockout_done;
    let transaction_clear = !d.transaction_open
        && !d.transaction_started
        && !d.users_deleted
        && !d.committed
        && !d.responded
        && !d.failed;
    let observe_devices = d.actor_active && d.same_account && lockouts_clear && transaction_clear;
    let lockout_devices = d.actor_active
        && d.same_account
        && d.devices_locked
        && !d.devices_lockout_done
        && !d.web_sessions_locked
        && !d.web_sessions_lockout_done
        && transaction_clear;
    let observe_web_sessions = d.actor_active
        && d.same_account
        && d.devices_locked
        && d.devices_lockout_done
        && !d.web_sessions_locked
        && !d.web_sessions_lockout_done
        && transaction_clear;
    let lockout_web_sessions = d.actor_active
        && d.same_account
        && d.devices_locked
        && d.devices_lockout_done
        && d.web_sessions_locked
        && !d.web_sessions_lockout_done
        && transaction_clear;
    let begin_transaction = d.actor_active
        && d.same_account
        && d.devices_locked
        && d.devices_lockout_done
        && d.web_sessions_locked
        && d.web_sessions_lockout_done
        && d.transaction_open
        && !d.transaction_started
        && !d.users_deleted
        && !d.committed
        && !d.responded
        && !d.failed;
    let deleting = d.actor_active
        && d.same_account
        && d.devices_locked
        && d.devices_lockout_done
        && d.web_sessions_locked
        && d.web_sessions_lockout_done
        && d.transaction_open
        && d.transaction_started
        && !d.users_deleted
        && !d.committed
        && !d.responded
        && !d.failed;
    let commit = d.actor_active
        && d.same_account
        && d.devices_locked
        && d.devices_lockout_done
        && d.web_sessions_locked
        && d.web_sessions_lockout_done
        && d.transaction_open
        && d.transaction_started
        && d.users_deleted
        && !d.committed
        && !d.responded
        && !d.failed;
    let done = (d.responded || d.failed)
        && !(d.responded && d.failed)
        && (!d.responded || (d.committed && d.users_deleted && d.transaction_started));
    (!matches!(d.stage, DeletionStage::ObserveDevices) || observe_devices)
        && (!matches!(d.stage, DeletionStage::LockoutDevices) || lockout_devices)
        && (!matches!(d.stage, DeletionStage::ObserveWebSessions) || observe_web_sessions)
        && (!matches!(d.stage, DeletionStage::LockoutWebSessions) || lockout_web_sessions)
        && (!matches!(d.stage, DeletionStage::BeginTransaction) || begin_transaction)
        && (!matches!(
            d.stage,
            DeletionStage::DeleteTable(_) | DeletionStage::DeleteUsers
        ) || deleting)
        && (!matches!(d.stage, DeletionStage::Commit) || commit)
        && (!matches!(d.stage, DeletionStage::Done) || done)
        && (!d.same_account || d.actor_active)
        && (!d.devices_locked || (d.actor_active && d.same_account))
        && (!d.devices_lockout_done || d.devices_locked)
        // A web-session lockout can only be instructed after the device
        // lockout was observed.
        && (!d.web_sessions_locked || (d.devices_lockout_done && d.same_account))
        && (!d.web_sessions_lockout_done || d.web_sessions_locked)
        // Effect-order invariant: the SQL transaction is only opened after
        // every device and every web session was locked out.
        && (!d.transaction_open || (d.devices_lockout_done && d.web_sessions_lockout_done))
        && (!d.transaction_started || d.transaction_open)
        && (!d.users_deleted || d.transaction_started)
        // A commit is only authorized after the users row was deleted inside
        // an open, started transaction.
        && (!d.committed || (d.users_deleted && d.transaction_started))
        && (!d.responded || d.committed)
        // A terminal failure never claims a commit.
        && (!d.failed || !d.committed)
}

/// Structural table comparison, kept independent of the derived `PartialEq`
/// implementation for hax extraction.
fn same_deletion_table(a: DeletionTable, b: DeletionTable) -> bool {
    matches!(
        (a, b),
        (DeletionTable::WebSessions, DeletionTable::WebSessions)
            | (DeletionTable::ShareInbox, DeletionTable::ShareInbox)
            | (DeletionTable::SharedItems, DeletionTable::SharedItems)
            | (DeletionTable::Sends, DeletionTable::Sends)
            | (DeletionTable::VaultChunks, DeletionTable::VaultChunks)
            | (DeletionTable::OramBuckets, DeletionTable::OramBuckets)
            | (DeletionTable::Devices, DeletionTable::Devices)
    )
}

/// Every effect the driver emits agrees with the state it produces. In
/// particular no table or `users` delete and no commit is emitted before the
/// transaction started, and no commit is emitted before the `users` delete
/// succeeded.
pub fn deletion_effect_is_sound(d: DeletionDriver, effect: DeletionEffect) -> bool {
    let common = d.actor_active && d.same_account && !d.failed;
    match effect {
        DeletionEffect::ScanDevices => {
            matches!(d.stage, DeletionStage::ObserveDevices)
                && common
                && !d.devices_locked
                && !d.devices_lockout_done
                && !d.web_sessions_locked
                && !d.web_sessions_lockout_done
                && !d.transaction_open
                && !d.transaction_started
                && !d.users_deleted
                && !d.committed
                && !d.responded
        }
        DeletionEffect::LockoutDevices => {
            common
                && matches!(d.stage, DeletionStage::LockoutDevices)
                && d.devices_locked
                && !d.devices_lockout_done
                && !d.web_sessions_locked
                && !d.transaction_open
                && !d.committed
                && !d.responded
        }
        DeletionEffect::ScanWebSessions => {
            common
                && matches!(d.stage, DeletionStage::ObserveWebSessions)
                && d.devices_locked
                && d.devices_lockout_done
                && !d.web_sessions_locked
                && !d.web_sessions_lockout_done
                && !d.transaction_open
                && !d.committed
                && !d.responded
        }
        DeletionEffect::LockoutWebSessions => {
            common
                && matches!(d.stage, DeletionStage::LockoutWebSessions)
                && d.devices_lockout_done
                && d.web_sessions_locked
                && !d.web_sessions_lockout_done
                && !d.transaction_open
                && !d.committed
                && !d.responded
        }
        DeletionEffect::BeginTransaction => {
            common
                && matches!(d.stage, DeletionStage::BeginTransaction)
                && d.devices_lockout_done
                && d.web_sessions_lockout_done
                && d.transaction_open
                && !d.transaction_started
                && !d.users_deleted
                && !d.committed
                && !d.responded
        }
        DeletionEffect::DeleteTable(table) => match d.stage {
            DeletionStage::DeleteTable(current) => {
                same_deletion_table(current, table)
                    && common
                    && d.devices_lockout_done
                    && d.web_sessions_lockout_done
                    && d.transaction_started
                    && !d.users_deleted
                    && !d.committed
                    && !d.responded
            }
            _ => false,
        },
        DeletionEffect::DeleteUsers => {
            common
                && matches!(d.stage, DeletionStage::DeleteUsers)
                && d.devices_lockout_done
                && d.web_sessions_lockout_done
                && d.transaction_started
                && !d.users_deleted
                && !d.committed
                && !d.responded
        }
        DeletionEffect::CommitTransaction => {
            common
                && matches!(d.stage, DeletionStage::Commit)
                && d.transaction_started
                && d.users_deleted
                && !d.committed
                && !d.responded
        }
        DeletionEffect::Complete => {
            matches!(d.stage, DeletionStage::Done)
                && d.actor_active
                && d.same_account
                && d.transaction_started
                && d.users_deleted
                && d.committed
                && d.responded
                && !d.failed
        }
        DeletionEffect::Fail(_) => {
            matches!(d.stage, DeletionStage::Done)
                && d.failed
                && !d.responded
                && !d.committed
        }
        DeletionEffect::Idle => true,
    }
}

fn transition(driver: DeletionDriver, effect: DeletionEffect) -> DeletionTransition {
    DeletionTransition { driver, effect }
}

fn idle(driver: DeletionDriver) -> DeletionTransition {
    transition(driver, DeletionEffect::Idle)
}

fn terminal(driver: DeletionDriver, failure: DeletionFailure) -> DeletionTransition {
    transition(
        DeletionDriver {
            stage: DeletionStage::Done,
            failed: true,
            ..driver
        },
        DeletionEffect::Fail(failure),
    )
}

/// Start a per-request account deletion. An actor the middleware did not
/// verify as an authenticated, active device — or a request whose effects are
/// not scoped to the session's own account — produces a terminal failure
/// without any effect, so no scan, lockout or SQL statement is authorized.
#[cfg_attr(hax, hax_lib::ensures(|result| {
    deletion_state_is_sound(result.driver)
        && deletion_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_deletion(actor: DeletionActorObservation) -> DeletionTransition {
    let actor_active = actor.authenticated && actor.device_active;
    if actor_active && actor.scoped_to_session_account {
        transition(
            DeletionDriver {
                stage: DeletionStage::ObserveDevices,
                actor_active: true,
                same_account: true,
                devices_locked: false,
                devices_lockout_done: false,
                web_sessions_locked: false,
                web_sessions_lockout_done: false,
                transaction_open: false,
                transaction_started: false,
                users_deleted: false,
                committed: false,
                responded: false,
                failed: false,
            },
            DeletionEffect::ScanDevices,
        )
    } else {
        let failure = if actor_active {
            DeletionFailure::CrossAccount
        } else {
            DeletionFailure::Unauthenticated
        };
        transition(
            DeletionDriver {
                stage: DeletionStage::Done,
                actor_active,
                same_account: false,
                devices_locked: false,
                devices_lockout_done: false,
                web_sessions_locked: false,
                web_sessions_lockout_done: false,
                transaction_open: false,
                transaction_started: false,
                users_deleted: false,
                committed: false,
                responded: false,
                failed: true,
            },
            DeletionEffect::Fail(failure),
        )
    }
}

fn on_devices_scanned(driver: DeletionDriver, observation: ScanObservation) -> DeletionTransition {
    match observation {
        ScanObservation::Rows => transition(
            DeletionDriver {
                stage: DeletionStage::LockoutDevices,
                devices_locked: true,
                ..driver
            },
            DeletionEffect::LockoutDevices,
        ),
        ScanObservation::QueryFailed => terminal(driver, DeletionFailure::DeviceScanStorage),
    }
}

fn on_device_lockout_completed(
    driver: DeletionDriver,
    observation: LockoutObservation,
) -> DeletionTransition {
    // The historical handler ignores a store-side lockout failure: the rows are
    // about to be deleted, so a failure only shortens the window in which a
    // stolen token still works. Both observations therefore continue.
    match observation {
        LockoutObservation::Applied | LockoutObservation::StorageFailed => transition(
            DeletionDriver {
                stage: DeletionStage::ObserveWebSessions,
                devices_lockout_done: true,
                ..driver
            },
            DeletionEffect::ScanWebSessions,
        ),
    }
}

fn on_web_sessions_scanned(
    driver: DeletionDriver,
    observation: ScanObservation,
) -> DeletionTransition {
    match observation {
        ScanObservation::Rows => transition(
            DeletionDriver {
                stage: DeletionStage::LockoutWebSessions,
                web_sessions_locked: true,
                ..driver
            },
            DeletionEffect::LockoutWebSessions,
        ),
        ScanObservation::QueryFailed => terminal(driver, DeletionFailure::WebSessionScanStorage),
    }
}

fn on_web_session_lockout_completed(
    driver: DeletionDriver,
    observation: LockoutObservation,
) -> DeletionTransition {
    match observation {
        LockoutObservation::Applied | LockoutObservation::StorageFailed => transition(
            DeletionDriver {
                stage: DeletionStage::BeginTransaction,
                web_sessions_lockout_done: true,
                transaction_open: true,
                ..driver
            },
            DeletionEffect::BeginTransaction,
        ),
    }
}

fn on_transaction_observed(
    driver: DeletionDriver,
    observation: TransactionObservation,
) -> DeletionTransition {
    match observation {
        TransactionObservation::Begun => transition(
            DeletionDriver {
                stage: DeletionStage::DeleteTable(DeletionTable::WebSessions),
                transaction_started: true,
                ..driver
            },
            DeletionEffect::DeleteTable(DeletionTable::WebSessions),
        ),
        TransactionObservation::Failed => terminal(driver, DeletionFailure::TransactionStorage),
    }
}

fn on_table_deleted(
    driver: DeletionDriver,
    table: DeletionTable,
    observation: TableDeleteObservation,
) -> DeletionTransition {
    match observation {
        TableDeleteObservation::Deleted => match table {
            DeletionTable::WebSessions => transition(
                DeletionDriver {
                    stage: DeletionStage::DeleteTable(DeletionTable::ShareInbox),
                    ..driver
                },
                DeletionEffect::DeleteTable(DeletionTable::ShareInbox),
            ),
            DeletionTable::ShareInbox => transition(
                DeletionDriver {
                    stage: DeletionStage::DeleteTable(DeletionTable::SharedItems),
                    ..driver
                },
                DeletionEffect::DeleteTable(DeletionTable::SharedItems),
            ),
            DeletionTable::SharedItems => transition(
                DeletionDriver {
                    stage: DeletionStage::DeleteTable(DeletionTable::Sends),
                    ..driver
                },
                DeletionEffect::DeleteTable(DeletionTable::Sends),
            ),
            DeletionTable::Sends => transition(
                DeletionDriver {
                    stage: DeletionStage::DeleteTable(DeletionTable::VaultChunks),
                    ..driver
                },
                DeletionEffect::DeleteTable(DeletionTable::VaultChunks),
            ),
            DeletionTable::VaultChunks => transition(
                DeletionDriver {
                    stage: DeletionStage::DeleteTable(DeletionTable::OramBuckets),
                    ..driver
                },
                DeletionEffect::DeleteTable(DeletionTable::OramBuckets),
            ),
            DeletionTable::OramBuckets => transition(
                DeletionDriver {
                    stage: DeletionStage::DeleteTable(DeletionTable::Devices),
                    ..driver
                },
                DeletionEffect::DeleteTable(DeletionTable::Devices),
            ),
            DeletionTable::Devices => transition(
                DeletionDriver {
                    stage: DeletionStage::DeleteUsers,
                    ..driver
                },
                DeletionEffect::DeleteUsers,
            ),
        },
        TableDeleteObservation::Failed => terminal(driver, DeletionFailure::TableStorage),
    }
}

fn on_users_deleted(
    driver: DeletionDriver,
    observation: UsersDeleteObservation,
) -> DeletionTransition {
    match observation {
        // The row count of this statement is the account-existence signal:
        // web-session-only accounts have no `devices` row, so a device count
        // can never stand in for it.
        UsersDeleteObservation::Deleted => transition(
            DeletionDriver {
                stage: DeletionStage::Commit,
                users_deleted: true,
                ..driver
            },
            DeletionEffect::CommitTransaction,
        ),
        // Dropping the guard rolls the transaction back.
        UsersDeleteObservation::Absent => terminal(driver, DeletionFailure::AccountNotFound),
        UsersDeleteObservation::Failed => terminal(driver, DeletionFailure::UsersStorage),
    }
}

fn on_commit_observed(
    driver: DeletionDriver,
    observation: CommitObservation,
) -> DeletionTransition {
    match observation {
        CommitObservation::Committed => transition(
            DeletionDriver {
                stage: DeletionStage::Done,
                committed: true,
                responded: true,
                ..driver
            },
            DeletionEffect::Complete,
        ),
        CommitObservation::Failed => terminal(driver, DeletionFailure::CommitStorage),
    }
}

/// The complete, total transition relation. Events that do not match the
/// current stage (and every event after `Done`) are ignored.
///
/// The third conjunct is the account-existence decision the transaction relies
/// on: a `CommitTransaction` effect exists exactly when the `users` delete was
/// observed from the `DeleteUsers` stage and reported the row deleted. A
/// zero-row (`Absent`) or failed `users` delete can therefore never authorize a
/// commit, which is what makes a second deletion of the same account unable to
/// commit.
#[cfg_attr(hax, hax_lib::requires(deletion_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    deletion_effect_is_sound(result.driver, result.effect)
        && (!deletion_state_is_sound(driver) || deletion_state_is_sound(result.driver))
        && (!matches!(result.effect, DeletionEffect::CommitTransaction)
            || (matches!(event, DeletionEvent::UsersDeleted(UsersDeleteObservation::Deleted))
                && matches!(driver.stage, DeletionStage::DeleteUsers)))
        && (!(matches!(event, DeletionEvent::UsersDeleted(UsersDeleteObservation::Deleted))
             && matches!(driver.stage, DeletionStage::DeleteUsers))
            || matches!(result.effect, DeletionEffect::CommitTransaction))
}))]
pub fn step(driver: DeletionDriver, event: DeletionEvent) -> DeletionTransition {
    match event {
        DeletionEvent::DevicesScanned(observation) => {
            if matches!(driver.stage, DeletionStage::ObserveDevices) {
                on_devices_scanned(driver, observation)
            } else {
                idle(driver)
            }
        }
        DeletionEvent::DeviceLockout(observation) => {
            if matches!(driver.stage, DeletionStage::LockoutDevices) {
                on_device_lockout_completed(driver, observation)
            } else {
                idle(driver)
            }
        }
        DeletionEvent::WebSessionsScanned(observation) => {
            if matches!(driver.stage, DeletionStage::ObserveWebSessions) {
                on_web_sessions_scanned(driver, observation)
            } else {
                idle(driver)
            }
        }
        DeletionEvent::WebSessionLockout(observation) => {
            if matches!(driver.stage, DeletionStage::LockoutWebSessions) {
                on_web_session_lockout_completed(driver, observation)
            } else {
                idle(driver)
            }
        }
        DeletionEvent::Transaction(observation) => {
            if matches!(driver.stage, DeletionStage::BeginTransaction) {
                on_transaction_observed(driver, observation)
            } else {
                idle(driver)
            }
        }
        DeletionEvent::TableDeleted(observation) => match driver.stage {
            DeletionStage::DeleteTable(table) => on_table_deleted(driver, table, observation),
            _ => idle(driver),
        },
        DeletionEvent::UsersDeleted(observation) => {
            if matches!(driver.stage, DeletionStage::DeleteUsers) {
                on_users_deleted(driver, observation)
            } else {
                idle(driver)
            }
        }
        DeletionEvent::Commit(observation) => {
            if matches!(driver.stage, DeletionStage::Commit) {
                on_commit_observed(driver, observation)
            } else {
                idle(driver)
            }
        }
    }
}

#[cfg_attr(hax, hax_lib::requires(deletion_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    deletion_effect_is_sound(result.driver, result.effect)
        && (!deletion_state_is_sound(driver) || deletion_state_is_sound(result.driver))
}))]
pub fn on_devices_scanned_event(
    driver: DeletionDriver,
    observation: ScanObservation,
) -> DeletionTransition {
    step(driver, DeletionEvent::DevicesScanned(observation))
}

#[cfg_attr(hax, hax_lib::requires(deletion_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    deletion_effect_is_sound(result.driver, result.effect)
        && (!deletion_state_is_sound(driver) || deletion_state_is_sound(result.driver))
}))]
pub fn on_device_lockout_event(
    driver: DeletionDriver,
    observation: LockoutObservation,
) -> DeletionTransition {
    step(driver, DeletionEvent::DeviceLockout(observation))
}

#[cfg_attr(hax, hax_lib::requires(deletion_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    deletion_effect_is_sound(result.driver, result.effect)
        && (!deletion_state_is_sound(driver) || deletion_state_is_sound(result.driver))
}))]
pub fn on_web_sessions_scanned_event(
    driver: DeletionDriver,
    observation: ScanObservation,
) -> DeletionTransition {
    step(driver, DeletionEvent::WebSessionsScanned(observation))
}

#[cfg_attr(hax, hax_lib::requires(deletion_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    deletion_effect_is_sound(result.driver, result.effect)
        && (!deletion_state_is_sound(driver) || deletion_state_is_sound(result.driver))
}))]
pub fn on_web_session_lockout_event(
    driver: DeletionDriver,
    observation: LockoutObservation,
) -> DeletionTransition {
    step(driver, DeletionEvent::WebSessionLockout(observation))
}

#[cfg_attr(hax, hax_lib::requires(deletion_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    deletion_effect_is_sound(result.driver, result.effect)
        && (!deletion_state_is_sound(driver) || deletion_state_is_sound(result.driver))
}))]
pub fn on_transaction_observed_event(
    driver: DeletionDriver,
    observation: TransactionObservation,
) -> DeletionTransition {
    step(driver, DeletionEvent::Transaction(observation))
}

#[cfg_attr(hax, hax_lib::requires(deletion_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    deletion_effect_is_sound(result.driver, result.effect)
        && (!deletion_state_is_sound(driver) || deletion_state_is_sound(result.driver))
}))]
pub fn on_table_deleted_event(
    driver: DeletionDriver,
    observation: TableDeleteObservation,
) -> DeletionTransition {
    step(driver, DeletionEvent::TableDeleted(observation))
}

#[cfg_attr(hax, hax_lib::requires(deletion_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    deletion_effect_is_sound(result.driver, result.effect)
        && (!deletion_state_is_sound(driver) || deletion_state_is_sound(result.driver))
}))]
pub fn on_users_deleted_event(
    driver: DeletionDriver,
    observation: UsersDeleteObservation,
) -> DeletionTransition {
    step(driver, DeletionEvent::UsersDeleted(observation))
}

#[cfg_attr(hax, hax_lib::requires(deletion_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    deletion_effect_is_sound(result.driver, result.effect)
        && (!deletion_state_is_sound(driver) || deletion_state_is_sound(result.driver))
}))]
pub fn on_commit_event(
    driver: DeletionDriver,
    observation: CommitObservation,
) -> DeletionTransition {
    step(driver, DeletionEvent::Commit(observation))
}

// ── Rust conformance tests ─────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const TABLES: [DeletionTable; 7] = [
        DeletionTable::WebSessions,
        DeletionTable::ShareInbox,
        DeletionTable::SharedItems,
        DeletionTable::Sends,
        DeletionTable::VaultChunks,
        DeletionTable::OramBuckets,
        DeletionTable::Devices,
    ];

    fn events() -> Vec<DeletionEvent> {
        let mut out = Vec::new();
        for observation in [ScanObservation::Rows, ScanObservation::QueryFailed] {
            out.push(DeletionEvent::DevicesScanned(observation));
            out.push(DeletionEvent::WebSessionsScanned(observation));
        }
        for observation in [
            LockoutObservation::Applied,
            LockoutObservation::StorageFailed,
        ] {
            out.push(DeletionEvent::DeviceLockout(observation));
            out.push(DeletionEvent::WebSessionLockout(observation));
        }
        for observation in [TransactionObservation::Begun, TransactionObservation::Failed] {
            out.push(DeletionEvent::Transaction(observation));
        }
        for observation in [TableDeleteObservation::Deleted, TableDeleteObservation::Failed] {
            out.push(DeletionEvent::TableDeleted(observation));
        }
        for observation in [
            UsersDeleteObservation::Deleted,
            UsersDeleteObservation::Absent,
            UsersDeleteObservation::Failed,
        ] {
            out.push(DeletionEvent::UsersDeleted(observation));
        }
        for observation in [CommitObservation::Committed, CommitObservation::Failed] {
            out.push(DeletionEvent::Commit(observation));
        }
        out
    }

    fn active() -> DeletionActorObservation {
        DeletionActorObservation {
            authenticated: true,
            device_active: true,
            scoped_to_session_account: true,
        }
    }

    /// Driver state at the start of `stage`, reached through the real
    /// transitions from `begin_deletion`.
    fn driver_at(stage: DeletionStage) -> DeletionDriver {
        let mut driver = begin_deletion(active()).driver;
        let mut guard = 0;
        while driver.stage != stage {
            let next = match driver.stage {
                DeletionStage::ObserveDevices => {
                    on_devices_scanned(driver, ScanObservation::Rows)
                }
                DeletionStage::LockoutDevices => {
                    on_device_lockout_completed(driver, LockoutObservation::Applied)
                }
                DeletionStage::ObserveWebSessions => {
                    on_web_sessions_scanned(driver, ScanObservation::Rows)
                }
                DeletionStage::LockoutWebSessions => {
                    on_web_session_lockout_completed(driver, LockoutObservation::Applied)
                }
                DeletionStage::BeginTransaction => {
                    on_transaction_observed(driver, TransactionObservation::Begun)
                }
                DeletionStage::DeleteTable(table) => {
                    on_table_deleted(driver, table, TableDeleteObservation::Deleted)
                }
                DeletionStage::DeleteUsers => {
                    on_users_deleted(driver, UsersDeleteObservation::Deleted)
                }
                DeletionStage::Commit => on_commit_observed(driver, CommitObservation::Committed),
                DeletionStage::Done => break,
            };
            driver = next.driver;
            guard += 1;
            assert!(guard < 32, "driver did not reach {stage:?}");
        }
        assert_eq!(driver.stage, stage);
        driver
    }

    fn stages() -> Vec<DeletionStage> {
        let mut out = vec![
            DeletionStage::ObserveDevices,
            DeletionStage::LockoutDevices,
            DeletionStage::ObserveWebSessions,
            DeletionStage::LockoutWebSessions,
            DeletionStage::BeginTransaction,
        ];
        out.extend(TABLES.iter().map(|t| DeletionStage::DeleteTable(*t)));
        out.push(DeletionStage::DeleteUsers);
        out.push(DeletionStage::Commit);
        out.push(DeletionStage::Done);
        out
    }

    #[test]
    fn exhaustive_stage_times_event_is_total_and_sound() {
        for stage in stages() {
            let driver = driver_at(stage);
            assert!(
                deletion_state_is_sound(driver),
                "driver at {stage:?} is unsound: {driver:?}"
            );
            for event in events() {
                let t = step(driver, event);
                assert!(
                    deletion_state_is_sound(t.driver),
                    "soundness lost from {stage:?} on {event:?}"
                );
                assert!(
                    deletion_effect_is_sound(t.driver, t.effect),
                    "effect soundness lost from {stage:?} on {event:?}"
                );
            }
        }
    }

    #[test]
    fn out_of_order_events_are_inert() {
        for stage in stages() {
            let driver = driver_at(stage);
            for event in events() {
                let expected = match (&driver.stage, &event) {
                    (DeletionStage::ObserveDevices, DeletionEvent::DevicesScanned(_)) => false,
                    (DeletionStage::LockoutDevices, DeletionEvent::DeviceLockout(_)) => false,
                    (
                        DeletionStage::ObserveWebSessions,
                        DeletionEvent::WebSessionsScanned(_),
                    ) => false,
                    (
                        DeletionStage::LockoutWebSessions,
                        DeletionEvent::WebSessionLockout(_),
                    ) => false,
                    (DeletionStage::BeginTransaction, DeletionEvent::Transaction(_)) => false,
                    (DeletionStage::DeleteTable(_), DeletionEvent::TableDeleted(_)) => false,
                    (DeletionStage::DeleteUsers, DeletionEvent::UsersDeleted(_)) => false,
                    (DeletionStage::Commit, DeletionEvent::Commit(_)) => false,
                    _ => true,
                };
                let t = step(driver, event);
                if expected {
                    assert_eq!(t.driver, driver, "non-matching event changed state");
                    assert_eq!(t.effect, DeletionEffect::Idle);
                }
            }
        }
    }

    #[test]
    fn done_is_inert_for_every_event() {
        for actor in [
            DeletionActorObservation {
                authenticated: false,
                device_active: true,
                scoped_to_session_account: true,
            },
            DeletionActorObservation {
                authenticated: true,
                device_active: false,
                scoped_to_session_account: true,
            },
            DeletionActorObservation {
                authenticated: true,
                device_active: true,
                scoped_to_session_account: false,
            },
        ] {
            let done = begin_deletion(actor).driver;
            assert_eq!(done.stage, DeletionStage::Done);
            for event in events() {
                let t = step(done, event);
                assert_eq!(t.driver, done);
                assert_eq!(t.effect, DeletionEffect::Idle);
            }
        }
    }

    #[test]
    fn lockouts_precede_the_transaction_and_commit_follows_users_delete() {
        let start = begin_deletion(active());
        assert_eq!(start.effect, DeletionEffect::ScanDevices);
        let driver = driver_at(DeletionStage::BeginTransaction);
        assert!(
            driver.devices_lockout_done && driver.web_sessions_lockout_done,
            "the transaction was authorized before both lockouts were observed"
        );
        assert!(!driver.transaction_started);

        let begun = on_transaction_observed(driver, TransactionObservation::Begun);
        assert_eq!(
            begun.effect,
            DeletionEffect::DeleteTable(DeletionTable::WebSessions)
        );
        assert!(begun.driver.transaction_started && !begun.driver.users_deleted);

        let mut driver = begun.driver;
        let mut table = DeletionTable::WebSessions;
        for (index, expected) in TABLES.iter().enumerate() {
            assert_eq!(expected.index() as usize, index);
            let t = on_table_deleted(driver, table, TableDeleteObservation::Deleted);
            driver = t.driver;
            if index + 1 < TABLES.len() {
                table = TABLES[index + 1];
                assert_eq!(t.effect, DeletionEffect::DeleteTable(table));
            } else {
                assert_eq!(t.effect, DeletionEffect::DeleteUsers);
                assert_eq!(driver.stage, DeletionStage::DeleteUsers);
            }
        }

        let t = on_users_deleted(driver, UsersDeleteObservation::Deleted);
        assert_eq!(t.effect, DeletionEffect::CommitTransaction);
        assert!(t.driver.users_deleted && !t.driver.committed);
        let t = on_commit_event(t.driver, CommitObservation::Committed);
        assert_eq!(t.effect, DeletionEffect::Complete);
        assert!(
            t.driver.committed && t.driver.responded && !t.driver.failed,
            "a successful commit did not produce a success response"
        );
    }

    #[test]
    fn absent_account_rolls_back_without_a_commit() {
        let driver = driver_at(DeletionStage::DeleteUsers);
        let t = on_users_deleted(driver, UsersDeleteObservation::Absent);
        assert_eq!(
            t.effect,
            DeletionEffect::Fail(DeletionFailure::AccountNotFound)
        );
        assert!(t.driver.failed && !t.driver.committed && !t.driver.responded);
        for event in events() {
            let t = step(t.driver, event);
            assert_eq!(t.effect, DeletionEffect::Idle);
        }
    }

    #[test]
    fn every_sql_failure_is_terminal_without_a_commit() {
        // Device scan failure: no lockout, no transaction.
        let t = on_devices_scanned_event(
            begin_deletion(active()).driver,
            ScanObservation::QueryFailed,
        );
        assert_eq!(
            t.effect,
            DeletionEffect::Fail(DeletionFailure::DeviceScanStorage)
        );
        assert!(!t.driver.devices_locked && !t.driver.transaction_open);

        // Web-session scan failure: the device lockout is already instructed.
        let driver = driver_at(DeletionStage::ObserveWebSessions);
        let t = on_web_sessions_scanned_event(driver, ScanObservation::QueryFailed);
        assert_eq!(
            t.effect,
            DeletionEffect::Fail(DeletionFailure::WebSessionScanStorage)
        );
        assert!(t.driver.devices_locked && !t.driver.transaction_open);

        // Transaction begin failure: nothing was deleted.
        let driver = driver_at(DeletionStage::BeginTransaction);
        let t = on_transaction_observed_event(driver, TransactionObservation::Failed);
        assert_eq!(
            t.effect,
            DeletionEffect::Fail(DeletionFailure::TransactionStorage)
        );
        assert!(!t.driver.transaction_started);

        // A table failure after some deletes: rollback, no commit.
        let driver = driver_at(DeletionStage::DeleteTable(DeletionTable::Sends));
        let t = on_table_deleted_event(driver, TableDeleteObservation::Failed);
        assert_eq!(t.effect, DeletionEffect::Fail(DeletionFailure::TableStorage));
        assert!(t.driver.transaction_started && !t.driver.committed);

        // The users delete itself failing.
        let driver = driver_at(DeletionStage::DeleteUsers);
        let t = on_users_deleted_event(driver, UsersDeleteObservation::Failed);
        assert_eq!(t.effect, DeletionEffect::Fail(DeletionFailure::UsersStorage));
        assert!(!t.driver.committed);

        // A commit failure is not reported as a success.
        let driver = driver_at(DeletionStage::Commit);
        let t = on_commit_event(driver, CommitObservation::Failed);
        assert_eq!(t.effect, DeletionEffect::Fail(DeletionFailure::CommitStorage));
        assert!(t.driver.failed && !t.driver.committed && !t.driver.responded);
    }

    #[test]
    fn a_lockout_storage_failure_still_deletes_the_account() {
        let mut driver = begin_deletion(active()).driver;
        let t = on_devices_scanned(driver, ScanObservation::Rows);
        driver = t.driver;
        let t = on_device_lockout_completed(driver, LockoutObservation::StorageFailed);
        driver = t.driver;
        assert_eq!(driver.stage, DeletionStage::ObserveWebSessions);
        assert!(driver.devices_lockout_done);
    }

    #[test]
    fn revoked_or_cross_account_actor_never_reaches_an_effect() {
        for (actor, failure) in [
            (
                DeletionActorObservation {
                    authenticated: false,
                    device_active: true,
                    scoped_to_session_account: true,
                },
                DeletionFailure::Unauthenticated,
            ),
            (
                DeletionActorObservation {
                    authenticated: true,
                    device_active: false,
                    scoped_to_session_account: true,
                },
                DeletionFailure::Unauthenticated,
            ),
            (
                DeletionActorObservation {
                    authenticated: true,
                    device_active: true,
                    scoped_to_session_account: false,
                },
                DeletionFailure::CrossAccount,
            ),
        ] {
            let start = begin_deletion(actor);
            assert_eq!(start.effect, DeletionEffect::Fail(failure));
            assert!(!start.driver.same_account && start.driver.failed);
            for event in events() {
                let t = step(start.driver, event);
                assert_eq!(t.effect, DeletionEffect::Idle);
            }
        }
    }

    /// Breadth-first exploration of every reachable driver state up to a
    /// bounded depth; every reachable state and emitted effect is sound.
    #[test]
    fn bfs_reachable_states_preserve_the_invariant() {
        let start = begin_deletion(active());
        assert!(deletion_state_is_sound(start.driver));
        let mut frontier = vec![start.driver];
        let mut seen = BTreeSet::new();
        seen.insert(format!("{:?}", start.driver));
        for _ in 0..14 {
            let mut next = Vec::new();
            for driver in frontier {
                for event in events() {
                    let t = step(driver, event);
                    assert!(deletion_state_is_sound(t.driver));
                    assert!(deletion_effect_is_sound(t.driver, t.effect));
                    if seen.insert(format!("{:?}", t.driver)) {
                        next.push(t.driver);
                    }
                }
            }
            frontier = next;
        }
        assert!(!seen.is_empty());
    }

    /// Every table is deleted exactly once, in the fixed order, and the users
    /// delete happens after all of them.
    #[test]
    fn table_order_is_fixed_and_each_table_is_deleted_once() {
        let driver = driver_at(DeletionStage::DeleteTable(DeletionTable::WebSessions));
        let mut seen = Vec::new();
        let mut driver = driver;
        loop {
            let table = match driver.stage {
                DeletionStage::DeleteTable(table) => table,
                DeletionStage::DeleteUsers => break,
                other => panic!("unexpected stage {other:?}"),
            };
            seen.push(table);
            let t = on_table_deleted(driver, table, TableDeleteObservation::Deleted);
            driver = t.driver;
        }
        assert_eq!(seen, TABLES.to_vec());
    }
}
