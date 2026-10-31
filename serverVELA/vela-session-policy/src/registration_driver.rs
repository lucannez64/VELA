//! Pure `POST /account/register` decision driver.
//!
//! `post_register` in `vela-server` performs the effectful steps: the per-IP
//! registration limiter, the optional `SELECT COUNT(*) FROM users` budget
//! query, the account and first-device `INSERT`s inside one transaction, the
//! PASETO issuance and the JTI tracking. This module owns every *decision*
//! between those effects:
//!
//! 1. the limiter must allow the request;
//! 2. when the operator configured `MAX_ACCOUNTS`, the counted budget must be
//!    below the limit (a failed or nonsensical count is terminal, never
//!    "unlimited");
//! 3. the presented identity and share keys must have decoded at the exact
//!    lengths the handler requires, including the share-key binding signature
//!    (the handler keeps the first exact error text in its `error` slot);
//! 4. one transaction is opened, exactly one account row and exactly one first
//!    device row are inserted, and the transaction commits only after the
//!    device row was observed inserted;
//! 5. only a committed account may issue and then track a token, and only a
//!    tracked token authorizes the response.
//!
//! The historical handler inserted the user and the device in two independent
//! statements: a device failure left an account row with no device. The driver
//! and the handler now put both inserts inside one transaction, so a failure
//! after the account insert rolls the account back — "the account and its
//! first device or nothing". That is the only intentional behaviour change in
//! this handler; every status, message, SQL text and store key is unchanged.
//!
//! The transition relation is total: an event that does not match the current
//! stage (and every event after `Done`) is ignored, so the unbounded trace
//! induction in `proofs/fstar/registration-driver-lemmas` quantifies over every
//! event list, not only the handler's intended order.

/// Request-side observations established before any effect. Key validity is a
/// pure decode/length/binding-signature fact computed by the handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationRequestObservation {
    pub has_account_limit: bool,
    /// `MAX_ACCOUNTS` as a signed limit (saturated at `i64::MAX`). Ignored
    /// when `has_account_limit` is false.
    pub account_limit: i64,
    /// `hybrid_ek` decoded at exactly 1600 bytes.
    pub identity_ek_valid: bool,
    /// `hybrid_vk` decoded at exactly 2624 bytes.
    pub identity_vk_valid: bool,
    /// `share_ek` is absent, or it decoded at exactly 1600 bytes, carried the
    /// required canonical timestamp and its binding signature verified under
    /// the presented identity key.
    pub share_ek_valid: bool,
}

/// Outcome of the per-IP registration limiter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateLimitObservation {
    Allowed,
    Denied,
}

/// Outcome of `SELECT COUNT(*) FROM users`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetObservation {
    Counted { count: i64 },
    QueryFailed,
}

/// Outcome of opening the one SQL transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionObservation {
    Begun,
    Failed,
}

/// Outcome of one `INSERT`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InsertObservation {
    Inserted,
    Failed,
}

/// Outcome of the commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitObservation {
    Committed,
    Failed,
}

/// Outcome of PASETO issuance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenObservation {
    Issued,
    Failed,
}

/// Outcome of JTI tracking.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrackObservation {
    Tracked,
    Failed,
}

/// Where the registration is in its decision sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationStage {
    RateLimit,
    AccountBudget,
    BeginTransaction,
    InsertAccount,
    InsertDevice,
    Commit,
    IssueToken,
    TrackToken,
    Done,
}

/// One driver event. The handler feeds exactly the observation it obtained
/// from the corresponding effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationEvent {
    RateLimitObserved(RateLimitObservation),
    BudgetObserved(BudgetObservation),
    TransactionObserved(TransactionObservation),
    AccountInserted(InsertObservation),
    DeviceInserted(InsertObservation),
    CommitObserved(CommitObservation),
    TokenObserved(TokenObservation),
    TrackObserved(TrackObservation),
}

/// Failure categories, preserving the handler's historical status/message
/// precedence. `InvalidRequest` keeps the handler's first decode error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationFailure {
    /// The per-IP limiter refused the request.
    RateLimited,
    /// A key decoded at the wrong length, was not base64, or the share-key
    /// binding signature failed. The handler keeps the exact message.
    InvalidRequest,
    /// The configured account ceiling was reached.
    AccountLimit,
    /// `SELECT COUNT(*)` failed.
    AccountCountStorage,
    /// The transaction could not be opened.
    TransactionStorage,
    /// The account insert failed. The transaction rolls back.
    AccountInsertStorage,
    /// The device insert failed. The transaction rolls back; no account
    /// survives.
    DeviceInsertStorage,
    /// The commit failed. An ambiguous commit is not reported as success.
    CommitStorage,
    /// PASETO issuance failed.
    TokenIssue,
    /// JTI tracking failed; the token must not be returned.
    TrackStorage,
}

/// The effect the handler must perform next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationEffect {
    /// Apply the per-IP registration limiter.
    CheckRateLimit,
    /// `SELECT COUNT(*) FROM users` (only when a ceiling is configured).
    CheckAccountBudget,
    /// Open the one SQL transaction.
    BeginTransaction,
    /// `INSERT INTO users ...`.
    InsertAccount,
    /// `INSERT INTO devices ...` for the first device.
    InsertDevice,
    /// Commit the transaction.
    CommitTransaction,
    /// Issue the PASETO token.
    IssueToken,
    /// Track the issued JTI before responding.
    TrackToken,
    /// Return the account/device/token response. The only success effect.
    Complete,
    /// Terminal failure. The handler drops the transaction, rolling it back.
    Fail(RegistrationFailure),
    /// Ignored/out-of-order event or a terminal driver.
    Idle,
}

/// Per-request driver state. Every field is a decision fact established by a
/// prior transition, never a claim about SQL, the clock or the token service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationDriver {
    pub stage: RegistrationStage,
    pub has_account_limit: bool,
    pub account_limit: i64,
    pub identity_ek_valid: bool,
    pub identity_vk_valid: bool,
    pub share_ek_valid: bool,
    /// The limiter allowed this request.
    pub rate_allowed: bool,
    /// The budget question (query or configured-skip) was resolved within the
    /// limit.
    pub budget_checked: bool,
    pub transaction_open: bool,
    pub transaction_started: bool,
    pub account_inserted: bool,
    pub device_inserted: bool,
    pub committed: bool,
    pub token_issued: bool,
    pub token_tracked: bool,
    /// The success response was authorized.
    pub responded: bool,
    /// A terminal failure was decided.
    pub failed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationTransition {
    pub driver: RegistrationDriver,
    pub effect: RegistrationEffect,
}

/// State invariant used by the Rust postconditions and independently restated
/// in the F* lemmas.
pub fn registration_state_is_sound(d: RegistrationDriver) -> bool {
    let pre = !d.transaction_open
        && !d.transaction_started
        && !d.account_inserted
        && !d.device_inserted
        && !d.committed
        && !d.token_issued
        && !d.token_tracked
        && !d.responded
        && !d.failed;
    let rate_limit =
        matches!(d.stage, RegistrationStage::RateLimit) && !d.budget_checked && pre;
    let account_budget = matches!(d.stage, RegistrationStage::AccountBudget)
        && d.rate_allowed
        && d.has_account_limit
        && !d.budget_checked
        && pre;
    let begin_transaction = matches!(d.stage, RegistrationStage::BeginTransaction)
        && d.rate_allowed
        && d.budget_checked
        && !d.transaction_open
        && !d.transaction_started
        && !d.account_inserted
        && !d.device_inserted
        && !d.committed
        && !d.token_issued
        && !d.token_tracked
        && !d.responded
        && !d.failed;
    let inserting = d.rate_allowed
        && d.budget_checked
        && d.transaction_open
        && d.transaction_started
        && !d.committed
        && !d.token_issued
        && !d.token_tracked
        && !d.responded
        && !d.failed;
    let insert_account = matches!(d.stage, RegistrationStage::InsertAccount)
        && inserting
        && !d.account_inserted
        && !d.device_inserted;
    let insert_device = matches!(d.stage, RegistrationStage::InsertDevice)
        && inserting
        && d.account_inserted
        && !d.device_inserted;
    let commit = matches!(d.stage, RegistrationStage::Commit)
        && d.rate_allowed
        && d.budget_checked
        && d.transaction_open
        && d.transaction_started
        && d.account_inserted
        && d.device_inserted
        && !d.committed
        && !d.token_issued
        && !d.token_tracked
        && !d.responded
        && !d.failed;
    let issue_token = matches!(d.stage, RegistrationStage::IssueToken)
        && d.rate_allowed
        && d.budget_checked
        && d.transaction_open
        && d.transaction_started
        && d.account_inserted
        && d.device_inserted
        && d.committed
        && !d.token_issued
        && !d.token_tracked
        && !d.responded
        && !d.failed;
    let track_token = matches!(d.stage, RegistrationStage::TrackToken)
        && d.rate_allowed
        && d.budget_checked
        && d.transaction_open
        && d.transaction_started
        && d.account_inserted
        && d.device_inserted
        && d.committed
        && d.token_issued
        && !d.token_tracked
        && !d.responded
        && !d.failed;
    let done = matches!(d.stage, RegistrationStage::Done)
        && (d.responded || d.failed)
        && !(d.responded && d.failed)
        && (!d.responded
            || (d.rate_allowed
                && d.budget_checked
                && d.transaction_started
                && d.account_inserted
                && d.device_inserted
                && d.committed
                && d.token_issued
                && d.token_tracked));
    (match d.stage {
        RegistrationStage::RateLimit => rate_limit,
        RegistrationStage::AccountBudget => account_budget,
        RegistrationStage::BeginTransaction => begin_transaction,
        RegistrationStage::InsertAccount => insert_account,
        RegistrationStage::InsertDevice => insert_device,
        RegistrationStage::Commit => commit,
        RegistrationStage::IssueToken => issue_token,
        RegistrationStage::TrackToken => track_token,
        RegistrationStage::Done => done,
    })
        && (!d.budget_checked || d.rate_allowed)
        && (!d.transaction_open || d.budget_checked)
        && (!d.transaction_started || d.transaction_open)
        && (!d.account_inserted || d.transaction_started)
        && (!d.device_inserted || d.account_inserted)
        && (!d.committed || d.device_inserted)
        && (!d.token_issued || d.committed)
        && (!d.token_tracked || d.token_issued)
        && (!d.responded || d.token_tracked)
}

/// Every effect the driver emits agrees with the state it produces.
pub fn registration_effect_is_sound(d: RegistrationDriver, effect: RegistrationEffect) -> bool {
    let valid_keys = d.identity_ek_valid && d.identity_vk_valid && d.share_ek_valid;
    let pre = !d.transaction_open
        && !d.transaction_started
        && !d.account_inserted
        && !d.device_inserted
        && !d.committed
        && !d.token_issued
        && !d.token_tracked
        && !d.responded
        && !d.failed;
    match effect {
        RegistrationEffect::CheckRateLimit => {
            matches!(d.stage, RegistrationStage::RateLimit) && !d.rate_allowed && pre
        }
        RegistrationEffect::CheckAccountBudget => {
            matches!(d.stage, RegistrationStage::AccountBudget)
                && d.rate_allowed
                && d.has_account_limit
                && !d.budget_checked
                && pre
        }
        RegistrationEffect::BeginTransaction => {
            matches!(d.stage, RegistrationStage::BeginTransaction)
                && d.rate_allowed
                && d.budget_checked
                && valid_keys
                && !d.transaction_open
                && pre
        }
        RegistrationEffect::InsertAccount => {
            matches!(d.stage, RegistrationStage::InsertAccount)
                && d.rate_allowed
                && d.budget_checked
                && d.transaction_open
                && d.transaction_started
                && !d.account_inserted
                && !d.device_inserted
                && !d.committed
                && !d.responded
                && !d.failed
        }
        RegistrationEffect::InsertDevice => {
            matches!(d.stage, RegistrationStage::InsertDevice)
                && d.rate_allowed
                && d.budget_checked
                && d.transaction_open
                && d.transaction_started
                && d.account_inserted
                && !d.device_inserted
                && !d.committed
                && !d.responded
                && !d.failed
        }
        RegistrationEffect::CommitTransaction => {
            matches!(d.stage, RegistrationStage::Commit)
                && d.transaction_open
                && d.transaction_started
                && d.account_inserted
                && d.device_inserted
                && !d.committed
                && !d.responded
                && !d.failed
        }
        RegistrationEffect::IssueToken => {
            matches!(d.stage, RegistrationStage::IssueToken)
                && d.committed
                && !d.token_issued
                && !d.responded
                && !d.failed
        }
        RegistrationEffect::TrackToken => {
            matches!(d.stage, RegistrationStage::TrackToken)
                && d.committed
                && d.token_issued
                && !d.token_tracked
                && !d.responded
                && !d.failed
        }
        RegistrationEffect::Complete => {
            matches!(d.stage, RegistrationStage::Done)
                && d.responded
                && d.transaction_started
                && d.account_inserted
                && d.device_inserted
                && d.committed
                && d.token_issued
                && d.token_tracked
                && !d.failed
        }
        RegistrationEffect::Fail(_) => {
            // A failure after the commit (token issue/tracking) still names
            // the committed account, but never authorizes a response.
            matches!(d.stage, RegistrationStage::Done) && d.failed && !d.responded
        }
        RegistrationEffect::Idle => true,
    }
}

fn transition(driver: RegistrationDriver, effect: RegistrationEffect) -> RegistrationTransition {
    RegistrationTransition { driver, effect }
}

fn idle(driver: RegistrationDriver) -> RegistrationTransition {
    transition(driver, RegistrationEffect::Idle)
}

fn terminal(
    driver: RegistrationDriver,
    failure: RegistrationFailure,
) -> RegistrationTransition {
    transition(
        RegistrationDriver {
            stage: RegistrationStage::Done,
            failed: true,
            ..driver
        },
        RegistrationEffect::Fail(failure),
    )
}

fn request_state(observation: RegistrationRequestObservation) -> RegistrationDriver {
    RegistrationDriver {
        stage: RegistrationStage::RateLimit,
        has_account_limit: observation.has_account_limit,
        account_limit: observation.account_limit,
        identity_ek_valid: observation.identity_ek_valid,
        identity_vk_valid: observation.identity_vk_valid,
        share_ek_valid: observation.share_ek_valid,
        rate_allowed: false,
        budget_checked: false,
        transaction_open: false,
        transaction_started: false,
        account_inserted: false,
        device_inserted: false,
        committed: false,
        token_issued: false,
        token_tracked: false,
        responded: false,
        failed: false,
    }
}

fn keys_valid(driver: RegistrationDriver) -> bool {
    driver.identity_ek_valid && driver.identity_vk_valid && driver.share_ek_valid
}

/// Start a per-request registration. The request-side key observations are
/// checked only after the limiter and the account budget, preserving the
/// historical error precedence (rate limit, then budget, then key decode).
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_state_is_sound(result.driver)
        && registration_effect_is_sound(result.driver, result.effect)
}))]
pub fn begin_registration(
    observation: RegistrationRequestObservation,
) -> RegistrationTransition {
    transition(
        request_state(observation),
        RegistrationEffect::CheckRateLimit,
    )
}

#[cfg_attr(hax, hax_lib::requires(
    registration_state_is_sound(driver)
        && matches!(driver.stage, RegistrationStage::RateLimit)
        && !driver.budget_checked
        && !driver.transaction_open
        && !driver.transaction_started
        && !driver.account_inserted
        && !driver.device_inserted
        && !driver.committed
        && !driver.token_issued
        && !driver.token_tracked
        && !driver.responded
        && !driver.failed
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_effect_is_sound(result.driver, result.effect)
        && (!registration_state_is_sound(driver)
            || registration_state_is_sound(result.driver))
}))]
fn on_rate_limit(
    driver: RegistrationDriver,
    observation: RateLimitObservation,
) -> RegistrationTransition {
    match observation {
        RateLimitObservation::Denied => terminal(driver, RegistrationFailure::RateLimited),
        RateLimitObservation::Allowed => {
            let allowed = RegistrationDriver {
                rate_allowed: true,
                ..driver
            };
            if driver.has_account_limit {
                transition(
                    RegistrationDriver {
                        stage: RegistrationStage::AccountBudget,
                        ..allowed
                    },
                    RegistrationEffect::CheckAccountBudget,
                )
            } else {
                begin_after_budget(RegistrationDriver {
                    budget_checked: true,
                    ..allowed
                })
            }
        }
    }
}

/// The budget question is resolved (or not configured): decode the keys and
/// either open the transaction or refuse the request with no SQL effect.
#[cfg_attr(hax, hax_lib::requires(
    driver.rate_allowed
        && driver.budget_checked
        && !driver.transaction_open
        && !driver.transaction_started
        && !driver.account_inserted
        && !driver.device_inserted
        && !driver.committed
        && !driver.token_issued
        && !driver.token_tracked
        && !driver.responded
        && !driver.failed
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_effect_is_sound(result.driver, result.effect)
        && registration_state_is_sound(result.driver)
}))]
fn begin_after_budget(driver: RegistrationDriver) -> RegistrationTransition {
    if keys_valid(driver) {
        transition(
            RegistrationDriver {
                stage: RegistrationStage::BeginTransaction,
                ..driver
            },
            RegistrationEffect::BeginTransaction,
        )
    } else {
        // The handler's `error` slot supplies the exact field message.
        terminal(driver, RegistrationFailure::InvalidRequest)
    }
}

#[cfg_attr(hax, hax_lib::requires(
    registration_state_is_sound(driver)
        && matches!(driver.stage, RegistrationStage::AccountBudget)
        && driver.rate_allowed
        && driver.has_account_limit
        && !driver.budget_checked
        && !driver.transaction_open
        && !driver.transaction_started
        && !driver.account_inserted
        && !driver.device_inserted
        && !driver.committed
        && !driver.token_issued
        && !driver.token_tracked
        && !driver.responded
        && !driver.failed
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_effect_is_sound(result.driver, result.effect)
        && (!registration_state_is_sound(driver)
            || registration_state_is_sound(result.driver))
}))]
fn on_budget(driver: RegistrationDriver, observation: BudgetObservation) -> RegistrationTransition {
    match observation {
        BudgetObservation::QueryFailed => {
            terminal(driver, RegistrationFailure::AccountCountStorage)
        }
        BudgetObservation::Counted { count } => {
            // A count that does not fit the configured limit is refused; a
            // negative count cannot come from `COUNT(*)` and fails closed.
            if count >= 0 && count < driver.account_limit {
                begin_after_budget(RegistrationDriver {
                    budget_checked: true,
                    ..driver
                })
            } else {
                terminal(driver, RegistrationFailure::AccountLimit)
            }
        }
    }
}

#[cfg_attr(hax, hax_lib::requires(
    registration_state_is_sound(driver)
        && matches!(driver.stage, RegistrationStage::BeginTransaction)
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_effect_is_sound(result.driver, result.effect)
        && (!registration_state_is_sound(driver)
            || registration_state_is_sound(result.driver))
}))]
fn on_transaction(
    driver: RegistrationDriver,
    observation: TransactionObservation,
) -> RegistrationTransition {
    match observation {
        TransactionObservation::Failed => {
            terminal(driver, RegistrationFailure::TransactionStorage)
        }
        TransactionObservation::Begun => transition(
            RegistrationDriver {
                stage: RegistrationStage::InsertAccount,
                transaction_open: true,
                transaction_started: true,
                ..driver
            },
            RegistrationEffect::InsertAccount,
        ),
    }
}

#[cfg_attr(hax, hax_lib::requires(
    registration_state_is_sound(driver)
        && matches!(driver.stage, RegistrationStage::InsertAccount)
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_effect_is_sound(result.driver, result.effect)
        && (!registration_state_is_sound(driver)
            || registration_state_is_sound(result.driver))
}))]
fn on_account_insert(
    driver: RegistrationDriver,
    observation: InsertObservation,
) -> RegistrationTransition {
    match observation {
        InsertObservation::Failed => {
            terminal(driver, RegistrationFailure::AccountInsertStorage)
        }
        InsertObservation::Inserted => transition(
            RegistrationDriver {
                stage: RegistrationStage::InsertDevice,
                account_inserted: true,
                ..driver
            },
            RegistrationEffect::InsertDevice,
        ),
    }
}

#[cfg_attr(hax, hax_lib::requires(
    registration_state_is_sound(driver)
        && matches!(driver.stage, RegistrationStage::InsertDevice)
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_effect_is_sound(result.driver, result.effect)
        && (!registration_state_is_sound(driver)
            || registration_state_is_sound(result.driver))
}))]
fn on_device_insert(
    driver: RegistrationDriver,
    observation: InsertObservation,
) -> RegistrationTransition {
    match observation {
        InsertObservation::Failed => {
            terminal(driver, RegistrationFailure::DeviceInsertStorage)
        }
        InsertObservation::Inserted => transition(
            RegistrationDriver {
                stage: RegistrationStage::Commit,
                device_inserted: true,
                ..driver
            },
            RegistrationEffect::CommitTransaction,
        ),
    }
}

#[cfg_attr(hax, hax_lib::requires(
    registration_state_is_sound(driver)
        && matches!(driver.stage, RegistrationStage::Commit)
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_effect_is_sound(result.driver, result.effect)
        && (!registration_state_is_sound(driver)
            || registration_state_is_sound(result.driver))
}))]
fn on_commit(
    driver: RegistrationDriver,
    observation: CommitObservation,
) -> RegistrationTransition {
    match observation {
        CommitObservation::Failed => terminal(driver, RegistrationFailure::CommitStorage),
        CommitObservation::Committed => transition(
            RegistrationDriver {
                stage: RegistrationStage::IssueToken,
                committed: true,
                ..driver
            },
            RegistrationEffect::IssueToken,
        ),
    }
}

#[cfg_attr(hax, hax_lib::requires(
    registration_state_is_sound(driver)
        && matches!(driver.stage, RegistrationStage::IssueToken)
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_effect_is_sound(result.driver, result.effect)
        && (!registration_state_is_sound(driver)
            || registration_state_is_sound(result.driver))
}))]
fn on_token(driver: RegistrationDriver, observation: TokenObservation) -> RegistrationTransition {
    match observation {
        TokenObservation::Failed => terminal(driver, RegistrationFailure::TokenIssue),
        TokenObservation::Issued => transition(
            RegistrationDriver {
                stage: RegistrationStage::TrackToken,
                token_issued: true,
                ..driver
            },
            RegistrationEffect::TrackToken,
        ),
    }
}

#[cfg_attr(hax, hax_lib::requires(
    registration_state_is_sound(driver)
        && matches!(driver.stage, RegistrationStage::TrackToken)
))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_effect_is_sound(result.driver, result.effect)
        && (!registration_state_is_sound(driver)
            || registration_state_is_sound(result.driver))
}))]
fn on_track(driver: RegistrationDriver, observation: TrackObservation) -> RegistrationTransition {
    match observation {
        TrackObservation::Failed => terminal(driver, RegistrationFailure::TrackStorage),
        TrackObservation::Tracked => transition(
            RegistrationDriver {
                stage: RegistrationStage::Done,
                token_tracked: true,
                responded: true,
                ..driver
            },
            RegistrationEffect::Complete,
        ),
    }
}

/// The complete, total transition relation. Events that do not match the
/// current stage (and every event after `Done`) are ignored.
#[cfg_attr(hax, hax_lib::requires(registration_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_effect_is_sound(result.driver, result.effect)
        && (!registration_state_is_sound(driver)
            || registration_state_is_sound(result.driver))
}))]
pub fn step(driver: RegistrationDriver, event: RegistrationEvent) -> RegistrationTransition {
    match event {
        RegistrationEvent::RateLimitObserved(observation) => {
            if matches!(driver.stage, RegistrationStage::RateLimit) {
                on_rate_limit(driver, observation)
            } else {
                idle(driver)
            }
        }
        RegistrationEvent::BudgetObserved(observation) => {
            if matches!(driver.stage, RegistrationStage::AccountBudget) {
                on_budget(driver, observation)
            } else {
                idle(driver)
            }
        }
        RegistrationEvent::TransactionObserved(observation) => {
            if matches!(driver.stage, RegistrationStage::BeginTransaction) {
                on_transaction(driver, observation)
            } else {
                idle(driver)
            }
        }
        RegistrationEvent::AccountInserted(observation) => {
            if matches!(driver.stage, RegistrationStage::InsertAccount) {
                on_account_insert(driver, observation)
            } else {
                idle(driver)
            }
        }
        RegistrationEvent::DeviceInserted(observation) => {
            if matches!(driver.stage, RegistrationStage::InsertDevice) {
                on_device_insert(driver, observation)
            } else {
                idle(driver)
            }
        }
        RegistrationEvent::CommitObserved(observation) => {
            if matches!(driver.stage, RegistrationStage::Commit) {
                on_commit(driver, observation)
            } else {
                idle(driver)
            }
        }
        RegistrationEvent::TokenObserved(observation) => {
            if matches!(driver.stage, RegistrationStage::IssueToken) {
                on_token(driver, observation)
            } else {
                idle(driver)
            }
        }
        RegistrationEvent::TrackObserved(observation) => {
            if matches!(driver.stage, RegistrationStage::TrackToken) {
                on_track(driver, observation)
            } else {
                idle(driver)
            }
        }
    }
}

#[cfg_attr(hax, hax_lib::requires(registration_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_effect_is_sound(result.driver, result.effect)
        && (!registration_state_is_sound(driver)
            || registration_state_is_sound(result.driver))
}))]
pub fn on_rate_limit_event(
    driver: RegistrationDriver,
    observation: RateLimitObservation,
) -> RegistrationTransition {
    step(driver, RegistrationEvent::RateLimitObserved(observation))
}

#[cfg_attr(hax, hax_lib::requires(registration_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_effect_is_sound(result.driver, result.effect)
        && (!registration_state_is_sound(driver)
            || registration_state_is_sound(result.driver))
}))]
pub fn on_budget_event(
    driver: RegistrationDriver,
    observation: BudgetObservation,
) -> RegistrationTransition {
    step(driver, RegistrationEvent::BudgetObserved(observation))
}

#[cfg_attr(hax, hax_lib::requires(registration_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_effect_is_sound(result.driver, result.effect)
        && (!registration_state_is_sound(driver)
            || registration_state_is_sound(result.driver))
}))]
pub fn on_transaction_event(
    driver: RegistrationDriver,
    observation: TransactionObservation,
) -> RegistrationTransition {
    step(driver, RegistrationEvent::TransactionObserved(observation))
}

#[cfg_attr(hax, hax_lib::requires(registration_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_effect_is_sound(result.driver, result.effect)
        && (!registration_state_is_sound(driver)
            || registration_state_is_sound(result.driver))
}))]
pub fn on_account_insert_event(
    driver: RegistrationDriver,
    observation: InsertObservation,
) -> RegistrationTransition {
    step(driver, RegistrationEvent::AccountInserted(observation))
}

#[cfg_attr(hax, hax_lib::requires(registration_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_effect_is_sound(result.driver, result.effect)
        && (!registration_state_is_sound(driver)
            || registration_state_is_sound(result.driver))
}))]
pub fn on_device_insert_event(
    driver: RegistrationDriver,
    observation: InsertObservation,
) -> RegistrationTransition {
    step(driver, RegistrationEvent::DeviceInserted(observation))
}

#[cfg_attr(hax, hax_lib::requires(registration_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_effect_is_sound(result.driver, result.effect)
        && (!registration_state_is_sound(driver)
            || registration_state_is_sound(result.driver))
}))]
pub fn on_commit_event(
    driver: RegistrationDriver,
    observation: CommitObservation,
) -> RegistrationTransition {
    step(driver, RegistrationEvent::CommitObserved(observation))
}

#[cfg_attr(hax, hax_lib::requires(registration_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_effect_is_sound(result.driver, result.effect)
        && (!registration_state_is_sound(driver)
            || registration_state_is_sound(result.driver))
}))]
pub fn on_token_event(
    driver: RegistrationDriver,
    observation: TokenObservation,
) -> RegistrationTransition {
    step(driver, RegistrationEvent::TokenObserved(observation))
}

#[cfg_attr(hax, hax_lib::requires(registration_state_is_sound(driver)))]
#[cfg_attr(hax, hax_lib::ensures(|result| {
    registration_effect_is_sound(result.driver, result.effect)
        && (!registration_state_is_sound(driver)
            || registration_state_is_sound(result.driver))
}))]
pub fn on_track_event(
    driver: RegistrationDriver,
    observation: TrackObservation,
) -> RegistrationTransition {
    step(driver, RegistrationEvent::TrackObserved(observation))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_request() -> RegistrationRequestObservation {
        RegistrationRequestObservation {
            has_account_limit: false,
            account_limit: 0,
            identity_ek_valid: true,
            identity_vk_valid: true,
            share_ek_valid: true,
        }
    }

    fn events() -> Vec<RegistrationEvent> {
        let mut out = Vec::new();
        for o in [RateLimitObservation::Allowed, RateLimitObservation::Denied] {
            out.push(RegistrationEvent::RateLimitObserved(o));
        }
        for o in [
            BudgetObservation::Counted { count: 0 },
            BudgetObservation::Counted { count: 5 },
            BudgetObservation::Counted { count: -1 },
            BudgetObservation::QueryFailed,
        ] {
            out.push(RegistrationEvent::BudgetObserved(o));
        }
        for o in [TransactionObservation::Begun, TransactionObservation::Failed] {
            out.push(RegistrationEvent::TransactionObserved(o));
        }
        for o in [InsertObservation::Inserted, InsertObservation::Failed] {
            out.push(RegistrationEvent::AccountInserted(o));
            out.push(RegistrationEvent::DeviceInserted(o));
        }
        for o in [CommitObservation::Committed, CommitObservation::Failed] {
            out.push(RegistrationEvent::CommitObserved(o));
        }
        for o in [TokenObservation::Issued, TokenObservation::Failed] {
            out.push(RegistrationEvent::TokenObserved(o));
        }
        for o in [TrackObservation::Tracked, TrackObservation::Failed] {
            out.push(RegistrationEvent::TrackObserved(o));
        }
        out
    }

    fn driver_at(stage: RegistrationStage, request: RegistrationRequestObservation) -> RegistrationDriver {
        let mut driver = begin_registration(request).driver;
        let mut guard = 0;
        while driver.stage != stage {
            let next = match driver.stage {
                RegistrationStage::RateLimit => {
                    on_rate_limit(driver, RateLimitObservation::Allowed)
                }
                RegistrationStage::AccountBudget => {
                    on_budget(driver, BudgetObservation::Counted { count: 0 })
                }
                RegistrationStage::BeginTransaction => {
                    on_transaction(driver, TransactionObservation::Begun)
                }
                RegistrationStage::InsertAccount => {
                    on_account_insert(driver, InsertObservation::Inserted)
                }
                RegistrationStage::InsertDevice => {
                    on_device_insert(driver, InsertObservation::Inserted)
                }
                RegistrationStage::Commit => on_commit(driver, CommitObservation::Committed),
                RegistrationStage::IssueToken => on_token(driver, TokenObservation::Issued),
                RegistrationStage::TrackToken => on_track(driver, TrackObservation::Tracked),
                RegistrationStage::Done => break,
            };
            driver = next.driver;
            guard += 1;
            assert!(guard < 12, "did not reach {stage:?}");
        }
        driver
    }

    #[test]
    fn every_state_and_effect_is_sound_exhaustively() {
        let requests = [
            valid_request(),
            RegistrationRequestObservation {
                has_account_limit: true,
                account_limit: 3,
                ..valid_request()
            },
            RegistrationRequestObservation {
                identity_ek_valid: false,
                ..valid_request()
            },
        ];
        let stages = [
            RegistrationStage::RateLimit,
            RegistrationStage::AccountBudget,
            RegistrationStage::BeginTransaction,
            RegistrationStage::InsertAccount,
            RegistrationStage::InsertDevice,
            RegistrationStage::Commit,
            RegistrationStage::IssueToken,
            RegistrationStage::TrackToken,
            RegistrationStage::Done,
        ];
        for request in requests {
            for stage in stages {
                if stage == RegistrationStage::AccountBudget && !request.has_account_limit {
                    continue;
                }
                if stage != RegistrationStage::RateLimit
                    && stage != RegistrationStage::AccountBudget
                    && stage != RegistrationStage::Done
                    && !keys_valid(request_state(request))
                {
                    continue;
                }
                let driver = driver_at(stage, request);
                assert!(registration_state_is_sound(driver), "{stage:?}: {driver:?}");
                for event in events() {
                    let t = step(driver, event);
                    assert!(
                        registration_state_is_sound(t.driver),
                        "{stage:?} on {event:?}: {t:?}"
                    );
                    assert!(registration_effect_is_sound(t.driver, t.effect));
                }
            }
        }
    }

    #[test]
    fn success_inserts_one_account_and_one_device_after_the_transaction() {
        let mut driver = begin_registration(valid_request()).driver;
        assert_eq!(driver.stage, RegistrationStage::RateLimit);
        let t = on_rate_limit(driver, RateLimitObservation::Allowed);
        // No configured ceiling: the budget query is skipped, not invented.
        assert_eq!(t.effect, RegistrationEffect::BeginTransaction);
        driver = t.driver;
        let t = on_transaction(driver, TransactionObservation::Begun);
        assert_eq!(t.effect, RegistrationEffect::InsertAccount);
        driver = t.driver;
        let t = on_account_insert(driver, InsertObservation::Inserted);
        assert_eq!(t.effect, RegistrationEffect::InsertDevice);
        driver = t.driver;
        let t = on_device_insert(driver, InsertObservation::Inserted);
        assert_eq!(t.effect, RegistrationEffect::CommitTransaction);
        driver = t.driver;
        let t = on_commit(driver, CommitObservation::Committed);
        assert_eq!(t.effect, RegistrationEffect::IssueToken);
        driver = t.driver;
        let t = on_token(driver, TokenObservation::Issued);
        assert_eq!(t.effect, RegistrationEffect::TrackToken);
        driver = t.driver;
        let t = on_track(driver, TrackObservation::Tracked);
        assert_eq!(t.effect, RegistrationEffect::Complete);
        assert!(t.driver.responded && !t.driver.failed);
    }

    #[test]
    fn a_device_insert_failure_rolls_the_account_back_and_never_commits() {
        let driver = driver_at(RegistrationStage::InsertDevice, valid_request());
        let t = on_device_insert(driver, InsertObservation::Failed);
        assert_eq!(
            t.effect,
            RegistrationEffect::Fail(RegistrationFailure::DeviceInsertStorage)
        );
        assert!(t.driver.failed && !t.driver.committed && !t.driver.responded);
        for event in events() {
            assert_eq!(step(t.driver, event).effect, RegistrationEffect::Idle);
        }
    }

    #[test]
    fn invalid_keys_are_refused_after_the_budget_without_sql() {
        let request = RegistrationRequestObservation {
            identity_vk_valid: false,
            ..valid_request()
        };
        let t = on_rate_limit(begin_registration(request).driver, RateLimitObservation::Allowed);
        assert_eq!(
            t.effect,
            RegistrationEffect::Fail(RegistrationFailure::InvalidRequest)
        );
        assert!(!t.driver.transaction_open && !t.driver.account_inserted);
    }

    #[test]
    fn the_account_ceiling_is_enforced_and_a_failed_count_is_terminal() {
        let request = RegistrationRequestObservation {
            has_account_limit: true,
            account_limit: 3,
            ..valid_request()
        };
        let driver = on_rate_limit(
            begin_registration(request).driver,
            RateLimitObservation::Allowed,
        )
        .driver;
        assert_eq!(driver.stage, RegistrationStage::AccountBudget);
        for (observation, failure) in [
            (
                BudgetObservation::Counted { count: 3 },
                RegistrationFailure::AccountLimit,
            ),
            (
                BudgetObservation::Counted { count: 4 },
                RegistrationFailure::AccountLimit,
            ),
            (
                BudgetObservation::Counted { count: -1 },
                RegistrationFailure::AccountLimit,
            ),
            (
                BudgetObservation::QueryFailed,
                RegistrationFailure::AccountCountStorage,
            ),
        ] {
            let t = on_budget(driver, observation);
            assert_eq!(t.effect, RegistrationEffect::Fail(failure));
            assert!(!t.driver.transaction_open);
        }
        let t = on_budget(driver, BudgetObservation::Counted { count: 2 });
        assert_eq!(t.effect, RegistrationEffect::BeginTransaction);
    }

    #[test]
    fn a_commit_failure_is_not_reported_as_success() {
        let driver = driver_at(RegistrationStage::Commit, valid_request());
        let t = on_commit(driver, CommitObservation::Failed);
        assert_eq!(
            t.effect,
            RegistrationEffect::Fail(RegistrationFailure::CommitStorage)
        );
        assert!(t.driver.failed && !t.driver.responded && !t.driver.committed);
    }

    #[test]
    fn an_untracked_token_is_never_returned() {
        let driver = driver_at(RegistrationStage::TrackToken, valid_request());
        let t = on_track(driver, TrackObservation::Failed);
        assert_eq!(
            t.effect,
            RegistrationEffect::Fail(RegistrationFailure::TrackStorage)
        );
        assert!(t.driver.token_issued && !t.driver.responded);
    }
}
