use rand::RngCore;
use serde::Serialize;
use std::env;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::{mpsc, Mutex};
use std::thread;
use std::time::Duration;
use tauri::{Manager, State, Emitter};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{TrayIconBuilder, TrayIconEvent, MouseButton};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
    JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::Foundation::CloseHandle;
use std::os::windows::io::AsRawHandle;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

pub struct JobObjectGuard {
    handle: windows::Win32::Foundation::HANDLE,
}

impl JobObjectGuard {
    pub fn new() -> Result<Self, String> {
        unsafe {
            let job = CreateJobObjectW(None, windows::core::PCWSTR::null())
                .map_err(|e| format!("Failed to create job object: {}", e))?;

            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ).map_err(|e| format!("Failed to set job object info: {}", e))?;

            Ok(Self { handle: job })
        }
    }

    pub fn assign_process(&self, process: &std::process::Child) -> Result<(), String> {
        unsafe {
            let handle_raw = process.as_raw_handle();
            let process_handle = windows::Win32::Foundation::HANDLE(handle_raw as *mut _);

            AssignProcessToJobObject(self.handle, process_handle)
                .map_err(|e| format!("Failed to assign process to job object: {}", e))
        }
    }
}

impl Drop for JobObjectGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

#[derive(Serialize, Clone)]
pub struct BackendHandle {
    port: u16,
    token: String,
    origin: String,
}

pub struct AppState {
    pub backend_handle: Mutex<Option<BackendHandle>>,
}

#[tauri::command]
fn get_backend_handle(state: State<AppState>) -> Option<BackendHandle> {
    let handle = state.backend_handle.lock().unwrap();
    handle.clone()
}

fn check_health(port: u16, token: &str) -> bool {
    if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
        let request = format!(
            "GET /health HTTP/1.1\r\n\
             Host: tauri.localhost\r\n\
             Authorization: Bearer {}\r\n\
             Connection: close\r\n\
             \r\n",
             token
        );
        if stream.write_all(request.as_bytes()).is_ok() {
            let mut response = String::new();
            if stream.read_to_string(&mut response).is_ok() {
                return response.contains("HTTP/1.1 200 OK") || response.contains("HTTP/1.0 200 OK");
            }
        }
    }
    false
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .manage(AppState {
            backend_handle: Mutex::new(None),
        })
        .setup(|app| {
            let handle = app.handle().clone();

            let show_i = MenuItem::with_id(app, "show", "Show Artemis", true, None::<&str>)?;
            let hide_i = MenuItem::with_id(app, "hide", "Hide Artemis", true, None::<&str>)?;
            let quit_i = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &hide_i, &quit_i])?;

            let _tray = TrayIconBuilder::new()
                .menu(&menu)
                .icon(app.default_window_icon().unwrap().clone())
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "quit" => {
                        app.exit(0);
                    }
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                    "hide" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.hide();
                        }
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click { button, .. } = event {
                        if button == MouseButton::Left {
                            let app = tray.app_handle();
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                    }
                })
                .build(app)?;

            // 1. Generate 256-bit token
            let mut token_bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut token_bytes);
            let token = hex::encode(token_bytes);

            let token_env = token.clone();

            // 2. Supervisor Thread
            thread::spawn(move || {
                let current_dir = env::current_dir().unwrap();
                let backend_dir = current_dir.join("../../backend");
                let python_exe = backend_dir.join(".venv/Scripts/python.exe");

                let mut retries = 0;
                let max_retries = 3;
                let mut _previous_job: Option<JobObjectGuard> = None;

                loop {
                    let mut cmd = Command::new(python_exe.clone());
                    cmd.arg("-m")
                       .arg("artemis.main")
                       .arg("--port")
                       .arg("0")
                       .arg("--host")
                       .arg("127.0.0.1")
                       .env("ARTEMIS_AUTH_TOKEN", token_env.clone())
                       .stdout(Stdio::piped())
                       .creation_flags(0x08000000); // CREATE_NO_WINDOW

                    let mut child = match cmd.spawn() {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("Failed to spawn python sidecar: {}", e);
                            break;
                        }
                    };

                    // 3. Assign to Windows Job Object
                    let job = match JobObjectGuard::new() {
                        Ok(j) => j,
                        Err(e) => {
                            eprintln!("{}", e);
                            break;
                        }
                    };

                    if let Err(e) = job.assign_process(&child) {
                        eprintln!("{}", e);
                        break;
                    }

                    _previous_job = Some(job);

                    // 4. Read handshake from stdout — with a 15-second timeout
                    //    (api.md §7: "shell retries handshake for 15 s, then FATAL UI").
                    //    A background thread performs the blocking read; the supervisor
                    //    thread waits on a channel with recv_timeout so it is never stuck.
                    let stdout = child.stdout.take().unwrap();
                    let (tx, rx) = mpsc::channel::<Option<String>>();

                    thread::spawn(move || {
                        let mut reader = BufReader::new(stdout);
                        let mut line = String::new();
                        match reader.read_line(&mut line) {
                            Ok(bytes) if bytes > 0 => { let _ = tx.send(Some(line)); }
                            _ => { let _ = tx.send(None); }
                        }
                    });

                    let handshake_line = match rx.recv_timeout(Duration::from_secs(15)) {
                        Ok(Some(line)) => line,
                        Ok(None) => {
                            // Reader closed without data (process exited cleanly without handshake)
                            eprintln!("Backend exited without emitting handshake");
                            let _ = child.wait();
                            retries += 1;
                            if retries > max_retries {
                                let _ = handle.emit("backend-fatal", ());
                                break;
                            }
                            thread::sleep(Duration::from_millis(500 * (1u64 << retries)));
                            continue;
                        }
                        Err(_) => {
                            // Timeout — kill the child and retry
                            eprintln!("Backend handshake timed out after 15 s; killing child");
                            let _ = child.kill();
                            let _ = child.wait();
                            retries += 1;
                            if retries > max_retries {
                                let _ = handle.emit("backend-fatal", ());
                                break;
                            }
                            thread::sleep(Duration::from_millis(500 * (1u64 << retries)));
                            continue;
                        }
                    };

                    #[derive(serde::Deserialize)]
                    #[allow(dead_code)]
                    struct Handshake {
                        port: u16,
                        pid: u32,
                        version: String,
                    }

                    let backend_port;
                    if let Ok(handshake) = serde_json::from_str::<Handshake>(handshake_line.trim()) {
                        backend_port = handshake.port;
                        let backend_handle = BackendHandle {
                            port: handshake.port,
                            token: token_env.clone(),
                            origin: "http://tauri.localhost".to_string(),
                        };

                        let state: State<AppState> = handle.state();
                        *state.backend_handle.lock().unwrap() = Some(backend_handle);

                        let _ = handle.emit("backend-ready", ());
                    } else {
                        eprintln!("Backend handshake JSON could not be parsed");
                        let _ = child.kill();
                        let _ = child.wait();
                        retries += 1;
                        if retries > max_retries {
                            let _ = handle.emit("backend-fatal", ());
                            break;
                        }
                        thread::sleep(Duration::from_millis(500 * (1u64 << retries)));
                        continue;
                    }

                    // 5. Supervision loop (Wait for child to exit OR health check failure)
                    let mut consecutive_failures = 0;
                    loop {
                        if let Ok(Some(_status)) = child.try_wait() {
                            break;
                        }

                        thread::sleep(Duration::from_secs(5));

                        if check_health(backend_port, &token_env) {
                            consecutive_failures = 0;
                        } else {
                            consecutive_failures += 1;
                            if consecutive_failures >= 3 {
                                eprintln!("Health check failed 3 times; killing backend");
                                let _ = child.kill();
                                let _ = child.wait();
                                break;
                            }
                        }
                    }

                    retries += 1;
                    if retries > max_retries {
                        let _ = handle.emit("backend-fatal", ());
                        break;
                    }

                    thread::sleep(Duration::from_millis(500 * (1u64 << retries)));
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![get_backend_handle])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::time::Duration;
    use std::thread;

    #[test]
    fn test_job_object_kills_child_on_drop() {
        // Spawn a long-running dummy process that doesn't terminate immediately.
        // `ping` is a native Windows binary that can run for a while.
        let mut child = Command::new("ping")
            .args(&["127.0.0.1", "-n", "100"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to spawn dummy process");

        // Create job and assign
        let job = JobObjectGuard::new().expect("Failed to create job object");
        job.assign_process(&child).expect("Failed to assign process");

        // Verify it's running
        thread::sleep(Duration::from_millis(500));
        assert!(child.try_wait().unwrap().is_none(), "Child should still be running");

        // Drop the job object. This should trigger KILL_ON_JOB_CLOSE
        drop(job);

        // Verify the process is terminated
        // We might need to wait a small amount for the OS to kill it
        let mut killed = false;
        for _ in 0..10 {
            if child.try_wait().unwrap().is_some() {
                killed = true;
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }

        assert!(killed, "Child process was not killed after Job Object was dropped");
    }

    #[test]
    fn test_check_health_success() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0; 1024];
                let _ = stream.read(&mut buf); // read request
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n");
            }
        });

        assert!(check_health(port, "test-token"), "Health check should succeed with 200 OK");
    }

    #[test]
    fn test_check_health_failure_bad_status() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0; 1024];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(b"HTTP/1.1 500 Internal Server Error\r\n\r\n");
            }
        });

        assert!(!check_health(port, "test-token"), "Health check should fail on 500");
    }

    #[test]
    fn test_check_health_failure_timeout() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0; 1024];
                let _ = stream.read(&mut buf);
                // Intentionally wait and do not respond to trigger timeout
                thread::sleep(Duration::from_secs(3));
            }
        });

        assert!(!check_health(port, "test-token"), "Health check should fail on timeout");
    }
}
