extern crate alloc;
use alloc::boxed::Box;

const HASH_DIGEST_LENGTH: usize = 64;

// like digest_t
#[repr(C)]
#[derive(Debug)]
#[derive(Copy, Clone)]
pub struct HashDigest
{
	pub digest: [u8; HASH_DIGEST_LENGTH],
	pub size: u32,
}

impl  HashDigest {
    pub const fn new() -> HashDigest{
        HashDigest {
            digest: [0;HASH_DIGEST_LENGTH],
            size: HASH_DIGEST_LENGTH as u32,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
#[derive(Clone)]
struct HashBuf {
    fst: u8,
    snd: *const u64,
}

#[repr(C)]
#[derive(Debug)]
#[derive(Clone)]
pub struct HashState {
    block_state: HashBuf,
    buf: *const u8,
    total_len: u64,
}

extern "C" {
    // fn _alloc_digest() -> *mut digest_t;
    // fn _free_digest(digest: *mut HashDigest) -> (); 
    fn _hash_init() -> *mut HashState;
    fn _hash_update(state: *const HashState, chunk: *mut u8, chunk_len: u32) -> u32;
    fn _hash_finish(state: *const HashState, output: *mut HashDigest) -> u32;
}

// ************ safe API ********

pub fn hash_init() -> Box<HashState> {
    let state_safe = unsafe {
        let state_ptr = _hash_init();
        Box::from_raw(state_ptr)
    };
    return state_safe;
}

pub fn hash_update_u64(state: &HashState, value: u64) -> u32 {
    let chunk = &mut value.to_ne_bytes() as *mut u8;
    let raw_state = state as *const HashState;

    return unsafe { _hash_update(raw_state, chunk, 8) };
}

pub fn hash_finish(state: HashState, output: &mut HashDigest) -> u32 {
    let raw_state = &state as *const HashState;
    let raw_digest = output as *mut HashDigest;
    // _hash_finish will free the state memory; HashState needs to be dropped,
    // thus state param as no reference
    return unsafe { _hash_finish(raw_state, raw_digest) };
}
