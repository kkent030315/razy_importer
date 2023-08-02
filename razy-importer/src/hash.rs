use core::ops::{BitOr, BitXor};

use ntapi::winapi::shared::ntdef::UNICODE_STRING;

use crate::OffsetHashPair;

pub struct ForwardedHashes {
    pub module_hash: u32,
    pub function_hash: u32,
}

#[inline(always)]
fn hash_single(value: u32, c: u8) -> u32 {
    let is_uppercase: bool = c >= b'A' && c <= b'Z';
    let mask: u32 = if !crate::CASE_SENSITIVE && is_uppercase {
        (c as u32) | (1 << 5)
    } else {
        c as u32
    };
    return value.bitxor(mask).wrapping_mul(const_random!(u32));
}

#[inline(always)]
pub fn khash_impl(str: &[u8], value: u32) -> u32 {
    if !str.is_empty() {
        return khash_impl(&str[1..], hash_single(value, str[0]));
    } else {
        return value;
    }
}

#[inline(always)]
pub fn khash(str: &[u8], offset: u32) -> OffsetHashPair {
    let hash_value: u64 = khash_impl(str, offset) as u64;
    return u64::from(offset).wrapping_shl(32).bitor(hash_value);
}

#[inline(always)]
pub fn hash(str: &[u8], offset: u32) -> u32 {
    let mut value: u32 = offset;
    for &c in str {
        if c == 0 {
            return value;
        }
        value = hash_single(value, c);
    }
    return value;
}

#[inline(always)]
pub fn hash_us(us: &UNICODE_STRING, offset: u32) -> u32 {
    let first: *mut u16 = us.Buffer as _;
    let last: *mut u16 = first.wrapping_add(us.Length as usize / size_of!(u16));
    let mut value: u32 = offset;
    let mut ptr: *mut u16 = first;
    while ptr < last {
        let c: u16 = unsafe { *ptr };
        value = hash_single(value, c as _);
        ptr = ptr.wrapping_add(1);
    }
    return value;
}

#[inline(always)]
pub fn hash_forwarded_slice(s: &[u8], offset: u32) -> ForwardedHashes {
    let mut res: ForwardedHashes = ForwardedHashes {
        module_hash: offset,
        function_hash: offset,
    };
    let mut iter: core::slice::Iter<'_, u8> = s.iter();
    while let Some(&c) = iter.next() {
        if c == b'.' {
            break;
        }
        res.module_hash = hash_single(res.module_hash, c);
    }
    if iter.next() == Some(&b'.') {
        for &c in iter {
            res.function_hash = hash_single(res.function_hash, c);
        }
    }
    return res;
}

#[inline(always)]
pub fn hash_forwarded(str: *const u8, offset: u32) -> ForwardedHashes {
    let mut res: ForwardedHashes = ForwardedHashes {
        module_hash: offset,
        function_hash: offset,
    };
    unsafe {
        let mut ptr: *const u8 = str;
        while *ptr != 0 {
            if *ptr == b'.' {
                break;
            }
            res.module_hash = hash_single(res.module_hash, *ptr);
            ptr = ptr.offset(1);
        }
        if *ptr != 0 {
            ptr = ptr.offset(1); // Skip the '.' character
            while *ptr != 0 {
                res.function_hash = hash_single(res.function_hash, *ptr);
                ptr = ptr.offset(1);
            }
        }
    }
    return res;
}
