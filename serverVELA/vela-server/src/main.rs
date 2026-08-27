use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    extract::Request,
    http::{header::HeaderName, HeaderValue},
    middleware::{self, Next},
    response::Response,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::{Args, Parser, Subcommand};
use vela_server::{
    config, data_lock, db, migration,
    migration::{ExportOptions, ImportOptions, InspectOptions, PassphraseSource},
    routes,
    routes::NativeHttps,
    share, sqldb, state, store,
    transport::{
        http3, tcp_tls,
        tls::{load_rustls_server_config, TlsConfigPaths},
    },
};

static X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
static ALT_SVC: HeaderName = HeaderName::from_static("alt-svc");

#[derive(Parser)]
#[command(name = "vela-server", version, about = "VELA sync/auth API server")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Serve,
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    Migrate {
        #[command(subcommand)]
        command: MigrateCommand,
    },
}

#[derive(Subcommand)]
enum AdminCommand {
    Keygen,
}

#[derive(Subcommand)]
enum MigrateCommand {
    Export(ExportArgs),
    Import(ImportArgs),
    Inspect(BundleArgs),
    Verify(BundleArgs),
}

#[derive(Args)]
struct ExportArgs {
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    env_file: PathBuf,
    #[arg(long)]
    data_dir: PathBuf,
    #[arg(long)]
    include_secrets: bool,
    #[arg(long)]
    include_deployment_config: Vec<PathBuf>,
    #[arg(long, conflicts_with = "passphrase_env")]
    passphrase: bool,
    #[arg(long)]
    passphrase_env: Option<String>,
}

#[derive(Args)]
struct ImportArgs {
    #[arg(long)]
    bundle: PathBuf,
    #[arg(long)]
    target_data_dir: PathBuf,
    #[arg(long)]
    target_env_file: PathBuf,
    #[arg(long)]
    replace: bool,
    #[arg(long, conflicts_with = "passphrase_env")]
    passphrase: bool,
    #[arg(long)]
    passphrase_env: Option<String>,
}

#[derive(Args)]
struct BundleArgs {
    #[arg(long)]
    bundle: PathBuf,
    #[arg(long, conflicts_with = "passphrase_env")]
    passphrase: bool,
    #[arg(long)]
    passphrase_env: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vela_server=info,tower_http=debug".into()),
        )
        .init();

    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => serve().await,
        Command::Admin { command } => run_admin(command),
        Command::Migrate { command } => run_migrate(command),
    }
}

fn run_admin(command: AdminCommand) -> anyhow::Result<()> {
    match command {
        AdminCommand::Keygen => {
            use pasetors::keys::{AsymmetricKeyPair, Generate};
            use pasetors::version4::V4;

            let kp = AsymmetricKeyPair::<V4>::generate()
                .map_err(|e| anyhow::anyhow!("PASETO key generation failed: {e:?}"))?;
            println!("{}", B64.encode(kp.secret.as_bytes()));
            Ok(())
        }
    }
}

fn run_migrate(command: MigrateCommand) -> anyhow::Result<()> {
    match command {
        MigrateCommand::Export(args) => {
            migration::export_bundle(ExportOptions {
                out: args.out,
                env_file: args.env_file,
                data_dir: args.data_dir,
                include_secrets: args.include_secrets,
                include_deployment_config: args.include_deployment_config,
                passphrase: passphrase_source(args.passphrase, args.passphrase_env),
            })?;
            println!("migration bundle exported");
            Ok(())
        }
        MigrateCommand::Import(args) => {
            migration::import_bundle(ImportOptions {
                bundle: args.bundle,
                target_data_dir: args.target_data_dir,
                target_env_file: args.target_env_file,
                replace: args.replace,
                passphrase: passphrase_source(args.passphrase, args.passphrase_env),
            })?;
            println!("migration bundle imported");
            Ok(())
        }
        MigrateCommand::Inspect(args) => {
            let manifest = migration::inspect_bundle(InspectOptions {
                bundle: args.bundle,
                passphrase: passphrase_source(args.passphrase, args.passphrase_env),
            })?;
            println!("{manifest}");
            Ok(())
        }
        MigrateCommand::Verify(args) => {
            migration::verify_bundle(InspectOptions {
                bundle: args.bundle,
                passphrase: passphrase_source(args.passphrase, args.passphrase_env),
            })?;
            println!("migration bundle verified");
            Ok(())
        }
    }
}

fn passphrase_source(prompt: bool, env: Option<String>) -> PassphraseSource {
    if let Some(name) = env {
        PassphraseSource::Env(name)
    } else {
        let _ = prompt;
        PassphraseSource::Prompt
    }
}

async fn serve() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    let config = config::Config::from_env()?;
    let _data_lock = data_lock::DataDirLock::try_acquire(
        std::path::Path::new(&config.db_path)
            .parent()
            .unwrap_or_else(|| std::path::Path::new("./data")),
    )?;
    tracing::info!(addr = %config.listen_addr, "VELA server starting");

    // The legacy stoolap database is opened only to bootstrap an existing
    // database into turso (and by `migrate import`); handlers never touch it.
    let stoolap_db = db::open_and_init(&config.db_path)?;
    tracing::info!(path = %config.db_path, "stoolap database opened (legacy read)");

    let kv = store::Store::open(&config.sled_path)?;
    tracing::info!(path = %config.sled_path, "sled embedded store opened");

    // Turso (SQLite-compatible) backend: the server's SQL store.
    let turso_pool = std::env::var("TURSO_DB_POOL_SIZE")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(8);
    let turso_path = std::path::Path::new(&config.db_path)
        .parent()
        .map(|p| p.join("vela-turso.db"))
        .unwrap_or_else(|| std::path::PathBuf::from("vela-turso.db"));
    let sqldb = std::sync::Arc::new(
        sqldb::TursoDb::open(&turso_path.to_string_lossy(), turso_pool).await?,
    );
    tracing::info!(path = %turso_path.display(), "turso database opened");

    // One-time migration: copy an existing stoolap database into the (empty)
    // turso database so an upgraded server serves its pre-existing data. Safe
    // on restart: a turso table that already has rows is left untouched.
    let copied = db::bootstrap_stoolap_into_turso(&stoolap_db, &sqldb).await?;
    if copied > 0 {
        tracing::warn!(rows = copied, "bootstrap: copied stoolap data into turso");
    }
    drop(stoolap_db);

    let state = Arc::new(
        state::AppStateInner::new(sqldb, kv, config.clone()).await?,
    );

    {
        let bg_sqldb = state.sqldb.clone();
        tokio::spawn(async move {
            share::inbox_cleanup_task(bg_sqldb).await;
        });
    }
    {
        let bg_sqldb = state.sqldb.clone();
        tokio::spawn(async move {
            vela_server::web_session::cleanup_task(bg_sqldb).await;
        });
    }
    {
        let bg_store = state.store.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
                match bg_store.cleanup_expired() {
                    Ok(n) => {
                        if n > 0 {
                            tracing::info!(removed = n, "sled expired-key cleanup");
                        }
                    }
                    Err(e) => tracing::error!(error = %e, "sled cleanup error"),
                }
            }
        });
    }

    let app = routes::build(state.clone())
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            config.max_body_bytes,
        ))
        // Bound how long a single request may occupy a handler (slow-request /
        // slowloris-style protection). Generous so legit large vault uploads on
        // slow links are unaffected.
        .layer(tower_http::timeout::TimeoutLayer::new(
            std::time::Duration::from_secs(120),
        ));

    let clear_addr: SocketAddr = config.listen_addr.parse()?;
    let clear_app = app.clone();

    let tls_paths = match (&config.tls_cert_path, &config.tls_key_path) {
        (Some(cert_path), Some(key_path)) => {
            Some(TlsConfigPaths::from_strings(cert_path, key_path))
        }
        _ => {
            tracing::warn!(
                "no TLS listener configured (TLS_CERT_PATH/TLS_KEY_PATH unset): VELA is \
                 serving cleartext HTTP only. Deploy it behind a TLS-terminating proxy \
                 (see serverVELA/DEPLOY_SYSTEMD.md) or configure the native TLS listener; \
                 clients expect an https origin (WEBAUTHN_RP_ORIGIN, CSP)."
            );
            None
        }
    };

    let tls_addr = config
        .tls_listen_addr
        .as_deref()
        .map(str::parse::<SocketAddr>)
        .transpose()?;
    let h3_addr = config
        .http3_listen_addr
        .as_deref()
        .map(str::parse::<SocketAddr>)
        .transpose()?;

    let tls_future = async {
        if let Some(addr) = tls_addr {
            let paths = tls_paths
                .as_ref()
                .expect("config validation requires TLS paths for TLS listener");
            let tls_config = Arc::new(load_rustls_server_config(paths, &[b"h2", b"http/1.1"])?);
            let alt_svc = if config.http3_enabled {
                h3_addr
                    .map(|addr| {
                        HeaderValue::from_str(&format!(
                            "h3=\":{}\"; ma={}",
                            addr.port(),
                            config.http3_alt_svc_max_age
                        ))
                    })
                    .transpose()?
            } else {
                None
            };
            let tls_app =
                app.clone()
                    .layer(middleware::from_fn(move |req: Request, next: Next| {
                        mark_native_https(req, next, alt_svc.clone())
                    }));
            tcp_tls::serve(addr, tls_app, tls_config).await?;
        }
        Ok::<(), anyhow::Error>(())
    };

    let h3_future = async {
        if config.http3_enabled {
            let addr = h3_addr.expect("config validation requires HTTP3_LISTEN_ADDR");
            let paths = tls_paths
                .as_ref()
                .expect("config validation requires TLS paths for HTTP/3");
            let h3_tls_config = load_rustls_server_config(paths, &[b"h3"])?;
            let h3_app = app.clone();
            http3::serve(addr, h3_app, h3_tls_config, config.max_body_bytes).await?;
        }
        Ok::<(), anyhow::Error>(())
    };

    tokio::try_join!(
        serve_cleartext(clear_addr, clear_app),
        tls_future,
        h3_future
    )?;

    Ok(())
}

async fn serve_cleartext(addr: SocketAddr, app: axum::Router) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "cleartext TCP listener active");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

async fn mark_native_https(mut req: Request, next: Next, alt_svc: Option<HeaderValue>) -> Response {
    req.extensions_mut().insert(NativeHttps);
    req.headers_mut()
        .insert(X_FORWARDED_PROTO.clone(), HeaderValue::from_static("https"));
    let mut response = next.run(req).await;
    if let Some(value) = alt_svc {
        response.headers_mut().insert(ALT_SVC.clone(), value);
    }
    response
}
