#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, RunEvent, WindowEvent,
};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use vela_desktop::ipc::server::IpcServer;
use vela_desktop::{commands, AppState};

fn setup_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(true)
        .init();
}

fn create_tray_menu(app: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let open = MenuItem::with_id(app, "open", "Open VELA", true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "lock", "Lock Now", true, None::<&str>)?;
    let sync = MenuItem::with_id(app, "sync", "Sync Now", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;

    Menu::with_items(app, &[&open, &lock, &sync, &quit])
}

fn setup_tray(app: &AppHandle) -> tauri::Result<()> {
    let menu = create_tray_menu(app)?;

    let icon = tauri::image::Image::from_bytes(include_bytes!("../icons/icon.png"))
        .map_err(|e| tauri::Error::from(e))?;

    let _tray = TrayIconBuilder::with_id("main-tray")
        .icon(icon)
        .menu(&menu)
        .tooltip("VELA — Locked")
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "lock" => {
                let state = app.state::<Arc<AppState>>();
                {
                    let mut session = state.session.write();
                    session.lock();
                }
                {
                    let mut crypto = state.crypto.write();
                    *crypto = None;
                }
                {
                    let mut vault = state.vault.write();
                    *vault = vela_desktop::vault::VaultStore::new();
                }
                info!("Session locked via tray");
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.emit("session-locked", ());
                }
            }
            "sync" => {
                info!("Manual sync triggered via tray");
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.emit("trigger-sync", ());
                }
            }
            "quit" => {
                info!("Application quit requested via tray");
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let app = tray.app_handle();
                if let Some(window) = app.get_webview_window("main") {
                    if window.is_visible().unwrap_or(false) {
                        let _ = window.hide();
                    } else {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
            }
        })
        .build(app)?;

    Ok(())
}

fn setup_global_shortcuts(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut};

    let shortcut = Shortcut::new(Some(Modifiers::CONTROL | Modifiers::ALT), Code::KeyV);

    let app_handle = app.clone();
    if let Err(e) = app
        .global_shortcut()
        .on_shortcut(shortcut, move |_app, _shortcut, _event| {
            info!("Global shortcut triggered: Quick search overlay");
            if let Some(window) = app_handle.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
                let _ = window.emit("open-quick-search", ());
            }
        })
    {
        error!("Failed to register global shortcut: {}", e);
    }

    Ok(())
}

fn main() {
    setup_logging();

    info!("Starting VELA Desktop Application");

    std::panic::set_hook(Box::new(|panic_info| {
        error!("Application panic: {:?}", panic_info);
    }));

    let result = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(Arc::new(AppState::default()))
        .setup(|app| {
            info!("Application setup starting");

            setup_tray(app.handle())?;
            if let Err(e) = setup_global_shortcuts(app.handle()) {
                error!("Failed to setup global shortcuts: {}", e);
            }

            let ipc_server = IpcServer::new();
            let app_handle = app.handle().clone();

            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("Failed to create tokio runtime");
                rt.block_on(async {
                    ipc_server.start(app_handle).await;
                });
            });
            info!("IPC server started on port 14597");

            if let Some(window) = app.get_webview_window("main") {
                let app_handle = app.handle().clone();
                window.on_window_event(move |event| {
                    if let WindowEvent::Focused(false) = event {
                        info!("Window lost focus");
                    }
                });
                let _ = window;
            }

            info!("Application setup complete");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::biometric::authenticate,
            commands::biometric::authenticate_password,
            commands::biometric::check_enrollment,
            commands::biometric::enroll,
            commands::biometric::setup_password_recovery,
            commands::session::get_session_status,
            commands::session::lock_session,
            commands::session::unlock_session,
            commands::session::unlock_session_with_password,
            commands::session::create_vault,
            commands::session::create_vault_with_password,
            commands::session::check_vault_exists,
            commands::session::reset_vault,
            commands::session::get_device_id,
            commands::vault::get_items,
            commands::vault::get_item,
            commands::vault::add_item,
            commands::vault::update_item,
            commands::vault::delete_item,
            commands::vault::search_items,
            commands::vault::generate_password,
            commands::vault::log_password_generated,
            commands::vault::get_items_by_type,
            commands::vault::get_vault_health,
            commands::vault::export_vault_bitwarden_json,
            commands::vault::import_vault_bitwarden_json,
            commands::vault::check_email_breach,
            commands::vault::check_all_vault_emails,
            commands::vault::check_password_breach,
            commands::vault::check_all_vault_passwords,
            commands::sync::trigger_sync,
            commands::sync::get_sync_status,
            commands::sync::resolve_conflict,
            commands::sync::set_server_url,
            commands::devices::get_devices,
            commands::devices::revoke_device,
            commands::devices::generate_enrollment_code,
            commands::devices::import_enrollment_code,
            commands::sharing::get_shares,
            commands::sharing::send_share,
            commands::sharing::accept_share,
            commands::sharing::decline_share,
            commands::sharing::delete_share,
            commands::audit::get_audit_log,
            commands::audit::log_audit_event,
            commands::audit::clear_audit_log,
            commands::settings::get_settings,
            commands::settings::update_settings,
            commands::settings::send_recovery_invite,
            commands::settings::start_recovery_webauthn_registration,
            commands::settings::finish_recovery_webauthn_registration,
            commands::settings::initiate_account_recovery,
            commands::settings::finish_account_recovery,
            commands::ipc::handle_autofill_request,
            commands::window::minimize_window,
            commands::window::maximize_window,
            commands::window::close_window,
            commands::window::toggle_always_on_top,
            commands::totp::generate_totp,
            commands::totp::verify_totp,
        ])
        .build(tauri::generate_context!());

    match result {
        Ok(app) => {
            info!("Application built successfully, entering main loop");
            app.run(
                |_app_handle, event| {
                    if let RunEvent::ExitRequested { api, .. } = event {}
                },
            );
        }
        Err(e) => {
            error!("Failed to build application: {:?}", e);
            std::process::exit(1);
        }
    }
}
