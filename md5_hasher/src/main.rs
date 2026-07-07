#[allow(non_upper_case_globals)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(dead_code)]
pub mod openssl_ffi {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use std::mem::MaybeUninit;

/* unsafe function for compute MD5 hash */
fn compute_md5(data: &[u8]) -> String {
    unsafe {
        let mut ctx = MaybeUninit::<openssl_ffi::MD5_CTX>::uninit();

        if openssl_ffi::MD5_Init(ctx.as_mut_ptr()) != 1 {
            panic!("OpenSSL MD5_Init failed");
        }

        let mut ctx = ctx.assume_init();
        if openssl_ffi::MD5_Update(
            &mut ctx, 
            data.as_ptr() as *const std::ffi::c_void, 
            data.len() as openssl_ffi::size_t
        ) != 1 {
            panic!("OpenSSL MD5_Update failed");
        }

        let mut digest = [0u8; openssl_ffi::MD5_DIGEST_LENGTH as usize];

        if openssl_ffi::MD5_Final(digest.as_mut_ptr(), &mut ctx) != 1 {
            panic!("OpenSSL MD5_Final failed");
        }

        // convert bytes to hex-string
        hex::encode(digest)
    }
}

fn main() {
    let input = b"Hello from rust and OpenSSL!";

    let hash_string = compute_md5(input);

    println!("input string: {}", String::from_utf8_lossy(input));
    println!("MD5 hash:     {}", hash_string);

    // check via assert
    // assert_eq!(hash_string, "99ba09228d4847e096fcf017fa72b7a0");
}
