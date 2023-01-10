use std::ptr;
use sha3::{Digest, Sha3_256, Keccak256};
use hs_bindgen::*;

#[hs_bindgen(sha3_256 :: Ptr CUChar -> CUInt -> Ptr CUChar -> IO ())]
fn sha3_256(msg_ptr: *const u8, size: u32, out_ptr: *const u8) {
    let msg = unsafe { std::slice::from_raw_parts(msg_ptr, size as usize) };
    let mut hasher = Sha3_256::new();
    hasher.update(msg);

    unsafe { ptr::copy_nonoverlapping(hasher.finalize().to_vec().as_ptr(), out_ptr as *mut u8, 32)}
}

#[hs_bindgen(keccak_256 :: Ptr CUChar -> CUInt -> Ptr CUChar -> IO ())]
fn keccak_256(msg_ptr: *const u8, size: u32, out_ptr: *const u8) {
    let msg = unsafe { std::slice::from_raw_parts(msg_ptr, size as usize) };
    let mut hasher = Keccak256::new();
    hasher.update(msg);

    unsafe { ptr::copy_nonoverlapping(hasher.finalize().to_vec().as_ptr(), out_ptr as *mut u8, 32)}
}

