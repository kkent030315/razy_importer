#![crate_type = "rlib"]
#![cfg_attr(all(not(test), not(debug_assertions)), no_std)]

#[cfg(test)]
mod test;

#[macro_use]
extern crate mem_macros;

#[cfg(test)]
#[macro_use]
extern crate const_random;

#[cfg(test)]
#[macro_use]
extern crate assert_hex;

pub mod hash;

use core::{arch::asm, ops::BitAnd};

use hash::ForwardedHashes;
use ntapi::{
    ntldr::LDR_DATA_TABLE_ENTRY,
    ntpebteb::PEB,
    ntpsapi::PEB_LDR_DATA,
    winapi::{
        shared::ntdef::UNICODE_STRING,
        um::winnt::{
            IMAGE_DATA_DIRECTORY, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS,
        },
    },
};

pub type OffsetHashPair = u64;

#[inline(always)]
pub fn get_hash(pair: OffsetHashPair) -> u32 {
    return pair.bitand(0xFFFFFFFF) as u32;
}

#[inline(always)]
pub fn get_offset(pair: OffsetHashPair) -> u32 {
    return pair.wrapping_shr(32) as u32;
}

#[inline(always)]
#[cfg(target_pointer_width = "64")]
unsafe fn __readgsqword(offset: u32) -> u64 {
    let gs_value: u64;
    asm!(
        "mov {}, gs:[{:e}]",
        lateout(reg) gs_value,
        in(reg) offset,
        options(nostack, pure, readonly),
    );
    return gs_value;
}

#[inline(always)]
#[cfg(target_pointer_width = "64")]
unsafe fn peb() -> *mut PEB {
    let peb: *mut PEB = __readgsqword(0x60) as *const u64 as *mut _;
    return peb;
}

#[inline(always)]
unsafe fn ldr() -> *mut PEB_LDR_DATA {
    let peb: *mut PEB = peb();
    let ldr: *mut PEB_LDR_DATA = (*peb).Ldr;
    return ldr;
}

#[inline(always)]
unsafe fn dos_header(base: u64) -> *mut IMAGE_DOS_HEADER {
    let dos_header: *mut IMAGE_DOS_HEADER = base as *const u64 as *mut _;
    return dos_header;
}

#[inline(always)]
unsafe fn nt_headers(base: u64) -> *mut IMAGE_NT_HEADERS {
    let dos_header: *mut IMAGE_DOS_HEADER = dos_header(base);
    let nt_headers: *mut IMAGE_NT_HEADERS = base.wrapping_add((*dos_header).e_lfanew as _) as _;
    return nt_headers;
}

#[inline(always)]
unsafe fn image_export_dir(base: u64) -> *mut IMAGE_EXPORT_DIRECTORY {
    let nt_headers: *mut IMAGE_NT_HEADERS = nt_headers(base);
    let data_dir: *const IMAGE_DATA_DIRECTORY =
        &((*nt_headers).OptionalHeader.DataDirectory[0]) as *const IMAGE_DATA_DIRECTORY;
    return base.wrapping_add((*data_dir).VirtualAddress as u64) as *const u64 as *mut _;
}

#[inline(always)]
unsafe fn image_export_data_dir(base: u64) -> *mut IMAGE_DATA_DIRECTORY {
    let nt_headers: *mut IMAGE_NT_HEADERS = nt_headers(base);
    let data_dir: *const IMAGE_DATA_DIRECTORY =
        &((*nt_headers).OptionalHeader.DataDirectory[0]) as *const IMAGE_DATA_DIRECTORY;
    return data_dir as _;
}

#[inline(always)]
unsafe fn ldr_data_entry_fl() -> *mut LDR_DATA_TABLE_ENTRY {
    let ldr: *mut PEB_LDR_DATA = ldr();
    let entry: *mut LDR_DATA_TABLE_ENTRY = (*ldr).InLoadOrderModuleList.Flink as *mut _;
    return entry;
}

#[inline(always)]
unsafe fn ldr_data_entry_bl() -> *mut LDR_DATA_TABLE_ENTRY {
    let ldr: *mut PEB_LDR_DATA = ldr();
    let entry: *mut LDR_DATA_TABLE_ENTRY = (*ldr).InLoadOrderModuleList.Blink as *mut _;
    return entry;
}

#[inline(always)]
pub unsafe fn get_module_base(ohp: OffsetHashPair, case_sensitive: bool) -> u64 {
    let mut entry: *mut LDR_DATA_TABLE_ENTRY = ldr_data_entry_fl();
    let end: *mut LDR_DATA_TABLE_ENTRY = ldr_data_entry_bl();
    while entry != end {
        let entry_hash: u32 = hash::hash_us(&(*entry).BaseDllName, get_offset(ohp), case_sensitive);
        if entry_hash == get_hash(ohp) {
            return (*entry).DllBase as _;
        }
        entry = (*entry).InLoadOrderLinks.Flink as _;
    }
    return 0;
}

#[inline(always)]
unsafe fn get_export_name(base: u64, index: usize) -> *const u8 {
    let ied: *mut IMAGE_EXPORT_DIRECTORY = image_export_dir(base);
    let names: *const u32 = base.wrapping_add((*ied).AddressOfNames as _) as *const u32;
    let name_ptr: *const u8 = base.wrapping_add(*names.offset(index as isize) as _) as *const u8;
    return name_ptr;
}

#[inline(always)]
unsafe fn get_export_addr(base: u64, index: usize) -> u64 {
    let ied: *const IMAGE_EXPORT_DIRECTORY = image_export_dir(base);
    let rvat: *const u32 = (base + (*ied).AddressOfFunctions as u64) as *const u32;
    let ordt: *const u16 = (base + (*ied).AddressOfNameOrdinals as u64) as *const u16;
    let name_offset: u32 = (*ordt.offset(index as isize)) as u32;
    let addr: u32 = *rvat.offset(name_offset as isize);
    return base.wrapping_add(addr as u64);
}

#[inline(always)]
unsafe fn is_forwarded(base: u64, export_address: u64) -> bool {
    let ied: *const IMAGE_EXPORT_DIRECTORY = unsafe { image_export_dir(base) };
    let ui_ied: u64 = ied as u64;
    let ied_data_dir: *mut IMAGE_DATA_DIRECTORY = image_export_data_dir(base);
    let ied_size: u32 = (*ied_data_dir).Size;
    return export_address > ui_ied && export_address < (ui_ied + ied_size as u64);
}

#[inline(always)]
unsafe fn is_ied_valid(base: u64) -> bool {
    let ied: *mut IMAGE_EXPORT_DIRECTORY = image_export_dir(base);
    let result: bool = ied as u64 != base;
    return result;
}

#[inline(always)]
unsafe fn get_export_count(base: u64) -> u32 {
    let ied: *mut IMAGE_EXPORT_DIRECTORY = image_export_dir(base);
    let size: u32 = (*ied).NumberOfNames;
    return size;
}

#[inline(always)]
pub unsafe fn get_export(base: u64, ohp: OffsetHashPair, case_sensitive: bool) -> u64 {
    if !is_ied_valid(base) {
        return 0;
    }
    let export_count: u32 = get_export_count(base);
    for index in 0..export_count {
        let name: *const u8 = get_export_name(base, index as _);
        let name_len: usize = strlen(name);
        let name_slice: &[u8] = core::slice::from_raw_parts(name, name_len);
        let entry_hash: u32 = hash::hash(name_slice, get_offset(ohp), case_sensitive);
        if entry_hash == get_hash(ohp) {
            let addr: u64 = get_export_addr(base, index as _);
            if is_forwarded(base, addr) {
                return get_export_forwarded(ohp, case_sensitive);
            }
            return addr;
        }
    }
    return 0;
}

#[inline(always)]
pub unsafe fn get_export_forwarded(ohp: OffsetHashPair, case_sensitive: bool) -> u64 {
    let mut hashes: ForwardedHashes = ForwardedHashes {
        module_hash: 0,
        function_hash: get_hash(ohp),
    };
    #[allow(unused_assignments)]
    let mut module_name: UNICODE_STRING = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: 0 as _,
    };
    let mut entry: *mut LDR_DATA_TABLE_ENTRY = ldr_data_entry_fl();
    let end: *mut LDR_DATA_TABLE_ENTRY = ldr_data_entry_bl();
    while entry != end {
        module_name = (*entry).BaseDllName;
        module_name.Length -= 8;
        if hashes.module_hash == 0
            || hash::hash_us(&module_name, get_offset(ohp), case_sensitive) == hashes.module_hash
        {
            let base: u64 = (*entry).DllBase as _;
            if is_ied_valid(base) {
                let export_count: u32 = get_export_count(base);
                'inner: for index in 0..export_count {
                    let name: *const u8 = get_export_name(base, index as _);
                    let name_len: usize = strlen(name);
                    let name_slice: &[u8] = core::slice::from_raw_parts(name, name_len);
                    let entry_hash: u32 = hash::hash(name_slice, get_offset(ohp), case_sensitive);
                    if entry_hash == hashes.function_hash {
                        let addr: u64 = get_export_addr(base, index as _);
                        if is_forwarded(base, addr) {
                            hashes = hash::hash_forwarded(
                                addr as *const u8,
                                get_offset(ohp),
                                case_sensitive,
                            );
                            entry = ldr_data_entry_fl();
                            break 'inner;
                        }
                        return addr;
                    }
                }
            }
        }
        entry = (*entry).InLoadOrderLinks.Flink as _;
    }
    return 0;
}

#[inline(always)]
unsafe fn strlen(s: *const u8) -> usize {
    let mut len: usize = 0;
    while *s.offset(len as isize) != 0 {
        len += 1;
    }
    return len;
}
