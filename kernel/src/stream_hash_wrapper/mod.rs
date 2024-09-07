extern crate alloc;
use alloc::boxed::Box;

use crate::error::SvsmError;

const HASH_DIGEST_LENGTH: usize = 64;

// like digest_t
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct HashDigest {
    pub digest: [u8; HASH_DIGEST_LENGTH],
    pub size: usize,
}

impl HashDigest {
    pub const fn new() -> HashDigest {
        HashDigest {
            digest: [0; HASH_DIGEST_LENGTH],
            size: HASH_DIGEST_LENGTH,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
struct HashBuf {
    fst: u8,
    snd: *const u64,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct HashState {
    block_state: HashBuf,
    buf: *const u8,
    total_len: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamError {
    InvalidAlgorithm,
    InvalidLength,
    MaximumLengthExceeded,
}

impl From<StreamError> for SvsmError {
    fn from(err: StreamError) -> Self {
        Self::Stream(err)
    }
}

impl StreamError {
    fn from_code(err_code: u32) -> Self {
        match err_code {
            1 => StreamError::InvalidAlgorithm,
            2 => StreamError::InvalidLength,
            3 => StreamError::MaximumLengthExceeded,
            _ => unreachable!(),
        }
    }
}

fn result_from_code(err_code: u32) -> Result<(), StreamError> {
    match err_code {
        0 => Ok(()),
        _ => Err(StreamError::from_code(err_code)),
    }
}

extern "C" {
    // fn _alloc_digest() -> *mut digest_t;
    // fn _free_digest(digest: *mut HashDigest) -> ();
    fn _hash_init() -> *mut HashState;
    fn _hash_update(state: *const HashState, chunk: *mut u8, chunk_len: u32) -> u32;
    fn _hash_finish(state: *const HashState, output: *mut HashDigest) -> u32;
}

// ************ safe API ********

impl HashState {
    pub fn hash_init() -> Box<Self> {
        let state_safe = unsafe {
            let state_ptr = _hash_init();
            Box::from_raw(state_ptr)
        };
        return state_safe;
    }

    pub fn hash_update_u64(&self, value: u64) -> Result<(), SvsmError> {
        let chunk = &mut value.to_ne_bytes() as *mut u8;
        let raw_state = self as *const HashState;

        let err_code = unsafe { _hash_update(raw_state, chunk, 8) };
        return result_from_code(err_code);
    }

    pub fn hash_update_u8(&self, value: u8) -> Result<(), SvsmError> {
        let chunk = &mut value.to_ne_bytes() as *mut u8;
        let raw_state = self as *const HashState;

        let err_code = unsafe { _hash_update(raw_state, chunk, 1) };
        return result_from_code(err_code);
    }

    pub fn hash_update_slice(&self, sl: &mut [u8]) -> Result<(), SvsmError> {
        let chunk = sl.as_mut_ptr();
        let raw_state = self as *const HashState;

        let err_code = unsafe { _hash_update(raw_state, chunk, sl.len()) };
        return result_from_code(err_code);
    }

    pub fn hash_finish(self, output: &mut HashDigest) -> Result<(), SvsmError> {
        let raw_state = &self as *const HashState;
        let raw_digest = output as *mut HashDigest;
        // _hash_finish will free the state memory; HashState needs to be dropped,
        // thus state param as no reference
        let err_code = unsafe { _hash_finish(raw_state, raw_digest) };
        return result_from_code(err_code);
    }
}
