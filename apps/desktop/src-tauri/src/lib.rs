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
use std::io::{BufRead, BufReader};

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
                let mut previous_job: Option<windows::Win32::Foundation::HANDLE> = None;
                
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
                    unsafe {
                        if let Some(old_job) = previous_job {
                            let _ = CloseHandle(old_job);
                        }
                        
                        let job = CreateJobObjectW(None, windows::core::PCWSTR::null()).expect("Failed to create job object");
                        
                        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
                        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                        
                        SetInformationJobObject(
                            job,
                            JobObjectExtendedLimitInformation,
                            &info as *const _ as *const std::ffi::c_void,
                            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                        ).expect("Failed to set job object info");
                        
                        let handle_raw = child.as_raw_handle();
                        let process_handle = windows::Win32::Foundation::HANDLE(handle_raw as *mut _);
                        
                        AssignProcessToJobObject(job, process_handle).expect("Failed to assign process to job object");
                        
                        previous_job = Some(job);
                    }
                    
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

                    if let Ok(handshake) = serde_json::from_str::<Handshake>(handshake_line.trim()) {
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

                    // 5. Wait for child to exit (normal: sidecar ran and terminated)
                    let _ = child.wait();

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
