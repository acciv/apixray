//! C ABI для apixray. Все строки — UTF-8, JSON. Возвращённые указатели
//! необходимо освобождать через `apixray_free`.

use std::ffi::{c_char, CStr, CString};

fn read_input(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .ok()
        .map(|s| s.to_string())
}

fn to_c(json: String) -> *mut c_char {
    CString::new(json)
        .unwrap_or_else(|_| CString::new("{\"error\":\"invalid string\"}").unwrap())
        .into_raw()
}

fn error_json(message: &str) -> String {
    format!("{{\"error\":{}}}", apixray_core::json_escape(message))
}

#[no_mangle]
pub extern "C" fn apixray_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn apixray_analyze(input: *const c_char) -> *mut c_char {
    match read_input(input) {
        Some(value) => to_c(apixray_core::analyze_json(&value)),
        None => to_c(error_json("null or invalid input")),
    }
}

#[no_mangle]
pub extern "C" fn apixray_scan(text: *const c_char) -> *mut c_char {
    match read_input(text) {
        Some(value) => to_c(apixray_core::scan_text_json(&value)),
        None => to_c(error_json("null or invalid input")),
    }
}

#[no_mangle]
pub extern "C" fn apixray_generate_fake(provider: *const c_char) -> *mut c_char {
    match read_input(provider) {
        Some(value) => to_c(apixray_core::generate_fake(&value)),
        None => to_c(error_json("null or invalid provider")),
    }
}

#[no_mangle]
pub extern "C" fn apixray_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }
}
