use rand::RngCore;
use serde::Serialize;
use std::env;
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use tauri::{AppHandle, Manager, State};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
    JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOBOBJECT_BASIC_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Threading::PROCESS_INFORMATION;
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
        .manage(AppState {
            backend_handle: Mutex::new(None),
        })
        .setup(|app| {
            let handle = app.handle().clone();
            
            // 1. Generate 256-bit token
            let mut token_bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut token_bytes);
            let token = hex::encode(token_bytes);
            
            let token_env = token.clone();
            
            // 2. Spawn python sidecar
            // In dev mode, we use the venv python. In prod, this would be the sidecar binary.
            let current_dir = env::current_dir().unwrap();
            let backend_dir = current_dir.join("../../backend");
            let python_exe = backend_dir.join(".venv/Scripts/python.exe");
            
            let mut cmd = Command::new(python_exe);
            cmd.arg("-m")
               .arg("artemis.main")
               .arg("--port")
               .arg("0")
               .arg("--host")
               .arg("127.0.0.1")
               .env("ARTEMIS_AUTH_TOKEN", token_env)
               .stdout(Stdio::piped())
               .creation_flags(0x08000000); // CREATE_NO_WINDOW
               
            let mut child = cmd.spawn().expect("Failed to spawn python sidecar");
            
            // 3. Assign to Windows Job Object
            unsafe {
                let job = CreateJobObjectW(None, None).expect("Failed to create job object");
                
                let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                
                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    &info as *const _ as *const std::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                ).expect("Failed to set job object info");
                
                // Get HANDLE from child process
                let handle_raw = child.as_raw_handle();
                let process_handle = windows::Win32::Foundation::HANDLE(handle_raw as *mut _);
                
                AssignProcessToJobObject(job, process_handle).expect("Failed to assign process to job object");
                
                // Leak the job handle so it stays open as long as the parent process lives
                std::mem::forget(job);
            }
            
            // 4. Read handshake from stdout
            let stdout = child.stdout.take().unwrap();
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            reader.read_line(&mut line).expect("Failed to read handshake");
            
            #[derive(serde::Deserialize)]
            struct Handshake {
                port: u16,
                pid: u32,
                version: String,
            }
            
            let handshake: Handshake = serde_json::from_str(&line).expect("Invalid handshake JSON");
            
            // 5. Store backend handle
            let backend_handle = BackendHandle {
                port: handshake.port,
                token,
                origin: "http://tauri.localhost".to_string(), // In dev we'll allow http://localhost:1420 as well via backend middleware
            };
            
            let state: State<AppState> = handle.state();
            *state.backend_handle.lock().unwrap() = Some(backend_handle);
            
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![get_backend_handle])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
