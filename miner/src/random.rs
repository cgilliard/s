//! The operating system's random source: `/dev/urandom` on Unix,
//! `BCryptGenRandom` (the system-preferred generator) on Windows.

/// Fills `buf` from the operating system's random source.
#[cfg(unix)]
pub fn fill(buf: &mut [u8]) -> std::io::Result<()> {
    std::io::Read::read_exact(&mut std::fs::File::open("/dev/urandom")?, buf)
}

/// Fills `buf` from the operating system's random source.
#[cfg(windows)]
pub fn fill(buf: &mut [u8]) -> std::io::Result<()> {
    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(alg: *mut std::ffi::c_void, buf: *mut u8, len: u32, flags: u32) -> i32;
    }
    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 2;
    for chunk in buf.chunks_mut(u32::MAX as usize) {
        // SAFETY: no algorithm handle with the system-preferred flag, and a
        // buffer valid for `len` bytes.
        let status = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                chunk.as_mut_ptr(),
                chunk.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status != 0 {
            return Err(std::io::Error::other(format!("BCryptGenRandom failed: {status:#x}")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn fills_with_different_bytes_each_time() {
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        super::fill(&mut a).unwrap();
        super::fill(&mut b).unwrap();
        assert_ne!(a, [0; 64]);
        assert_ne!(a, b);
    }
}
