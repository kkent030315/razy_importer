#![allow(non_snake_case)]

#[macro_use]
extern crate razy_importer_macros;

use ntapi::winapi::shared::minwindef::ULONG;

fn main() {
    let NtGetCurrentProcessorNumber: unsafe extern "system" fn() -> ULONG =
        ri_fn!("NtGetCurrentProcessorNumber", ri_mod!("ntdll.dll"));
    println!("NtGetCurrentProcessorNumber={}", unsafe { NtGetCurrentProcessorNumber() });
}