#![allow(non_snake_case)]

#[macro_use]
extern crate razy_importer_macros;

use winapi::shared::minwindef::ULONG;
use winapi::shared::minwindef::DWORD;

#[inline(never)]
#[no_mangle]
#[export_name = "nt"]
fn nt() -> u32 {
    let NtGetCurrentProcessorNumber: unsafe extern "system" fn() -> ULONG =
        ri_fn!("NtGetCurrentProcessorNumber");
    return unsafe { NtGetCurrentProcessorNumber() };
}

#[inline(never)]
#[no_mangle]
#[export_name = "k32"]
fn k32() -> u32 {
    let GetCurrentProcessorNumber: unsafe extern "system" fn() -> DWORD =
        ri_fn!("GetCurrentProcessorNumber");
    return unsafe { GetCurrentProcessorNumber() };
}

#[inline(never)]
fn main() {
    let res_nt: u32 = nt();
    println!("nt: {}", res_nt);
    let res_k32: u32 = k32();
    println!("k32: {}", res_k32);
}
