use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn main() {
    let exe_dir = env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    let script = exe_dir.join("vela-native-messaging-host.py");

    let interpreters = ["python3", "python", "py"];
    for interpreter in interpreters {
        let status = Command::new(interpreter)
            .arg(&script)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status();

        match status {
            Ok(status) => std::process::exit(status.code().unwrap_or(1)),
            Err(_) => continue,
        }
    }

    eprintln!("Unable to start Python for VELA native messaging host");
    std::process::exit(1);
}
