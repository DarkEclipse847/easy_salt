//! This is a simple crate providing salt for commonly used hashing algorithms.
//! This crate will give you opportunity to generate **tuple** of type `(hash, salt)` for your needs.
//!
//! ## List of hashing algorithms
//! - [ ] SHA:
//!     - [x] sha-1
//!     - [x] sha-224
//!     - [x] sha-256
//!     - [x] sha-384
//!     - [x] sha-512
//!     - [ ] sha3-224
//!     - [ ] sha3-256
//!     - [ ] sha3-384
//!     - [ ] sha3-512
//! - [ ] MD:
//!     - [ ] md2
//!     - [ ] md4
//!     - [ ] md5
//! - [ ] Bcrypt
//! - [ ] Argon2:
//!     - [ ] Argon2d
//!     - [ ] Argon2i
//!     - [ ] Argon2id
//!
//! ## Example
//! ```
//! extern crate easy_salt;
//! use easy_salt::salty_sha::*;
//!
//! fn main(){
//!     let length: u64 = 8;
//!     let hash = salty_sha256("hello", length);
//!     println!("Hash: {:?}, Salt: {:?}", hash.0, hash.1);
//!     
//!     let another_hash = salty_sha256("hello", length);
//!     println!("Second Hash: {:?}, Second salt: {:?}", another_hash.0, another_hash.1);
//!
//!     assert_ne!(hash.0, another_hash.0);
//! }
//! ```
//!
//! There is a plan to change logic so instead of tuple functions will return struct with fields `hash` and `salt` respectfully for better readability

use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;

/// `generate_salt` function will generate random string of **chars** with given length
/// ## Example
/// ```
/// extern crate easy_salt;
/// use easy_salt::*;
/// fn main(){
///     let length: u64 = 8;
///     let random_str: String = generate_salt(length);
///     //will print out something like "H6giL0e3"
///     println!("{}", random_str);
/// }
/// ```
pub fn generate_salt(length: u64) -> String{
    let salt: String = (0..length)
        .map(|_| thread_rng().sample(Alphanumeric) as char)
        .collect();
    salt
}

/// This module provides salted SHA-* hashing algorithms
///
/// SHA-1 and SHA-2 algorithms have some vulnerabilities due to collision attacks. Althrough this is pretty rare, i'll recommend using SHA-3 hash also known as Kekkak
/// 
/// ##Example
/// ```
/// extern crate easy_salt;
/// use easy_salt::salty_sha::*;
/// 
/// fn main(){
///     let hash = salty_sha256("some string", 6); //first argument is string you need to be hashed, second argument is the salt length
///     println!("Hash: {:?}, Salt: {:?}", hash.0, hash.1); //Note, that variable hash is a tuple, so it returns (hash, salt)
/// }
pub mod salty_sha{
    use crate::generate_salt;
    extern crate easy_hasher;
    use easy_hasher::easy_hasher::*;

    fn to_sha1(str: &str) -> String{ 
        let result = sha1(&str.to_string()).to_hex_string();
        result
    }
    fn to_sha224(str: &str) -> String{ 
        let result = sha224(&str.to_string()).to_hex_string();
        result
    }
    fn to_sha256(str: &str) -> String{ 
        let result = sha256(&str.to_string()).to_hex_string();
        result
    }
    fn to_sha384(str: &str) -> String{ 
        let result = sha384(&str.to_string()).to_hex_string();
        result
    }
    fn to_sha512(str: &str) -> String{ 
        let result = sha512(&str.to_string()).to_hex_string();
        result
    }

    /// Function, which returns sha-1 salted hash
    /// Salt is added to the beginning of the string
    ///
    /// ##Example
    /// ```
    /// extern crate easy_salt;
    /// use easy_salt::salty_sha::salty_sha1;
    /// 
    /// fn main(){
    ///     //Note that sha-1 has some major vulnerabilities, be careful using it!
    ///     let hash = salty_sha1("some string", 6); //first argument is string you need to be hashed, second argument is the salt length
    ///     println!("Hash: {:?}, Salt: {:?}", hash.0, hash.1); //Note, that variable hash is a tuple, so it returns (hash, salt)
    /// }
    /// ```
    pub fn salty_sha1(str: &str, salt_length: u64) -> (String, String){
        let salt = generate_salt(salt_length);
        let encrypted_string = to_sha1(&(salt.to_string() + str));
        return (encrypted_string, salt);
    }

    /// Generates salted sha-224 hash
    /// Salt is added to the beginning of the string
    ///
    /// ##Example
    /// ```
    /// extern crate easy_salt;
    /// use easy_salt::salty_sha::salty_sha224;
    /// 
    /// fn main(){
    ///     let hash = salty_sha224("some string", 6); //first argument is string you need to be hashed, second argument is the salt length
    ///     println!("Hash: {:?}, Salt: {:?}", hash.0, hash.1); //Note, that variable hash is a tuple, so it returns (hash, salt)
    /// }
    /// ```
    pub fn salty_sha224(str: &str, salt_length: u64) -> (String, String){
        let salt = generate_salt(salt_length);
        let encrypted_string = to_sha224(&(salt.to_string() + str));
        return (encrypted_string, salt);
    }
    
    /// Generates salted sha-256 string
    /// Returns tuple (hash, salt)
    /// Salt is added to the beginning of the string
    ///
    /// ##Example
    /// ```
    /// extern crate easy_salt;
    /// use easy_salt::salty_sha::salty_sha256;
    /// 
    /// fn main(){
    ///     let hash = salty_sha256("some string", 6); //first argument is string you need to be hashed, second argument is the salt length
    ///     println!("Hash: {:?}, Salt: {:?}", hash.0, hash.1); //Note, that variable hash is a tuple, so it returns (hash, salt)
    /// }
    /// ```
    pub fn salty_sha256(str: &str, salt_length: u64) -> (String, String){
        let salt = generate_salt(salt_length);
        let encrypted_string = to_sha256(&(salt.to_string() + str));
        return (encrypted_string, salt);
    }

    /// Function, which returns sha-384 salted hash
    /// Salt is added to the beginning of the string
    ///
    /// ##Example
    /// ```
    /// extern crate easy_salt;
    /// use easy_salt::salty_sha::salty_sha384;
    /// 
    /// fn main(){
    ///     let hash = salty_sha384("some string", 6); //first argument is string you need to be hashed, second argument is the salt length
    ///     println!("Hash: {:?}, Salt: {:?}", hash.0, hash.1); //Note, that variable hash is a tuple, so it returns (hash, salt)
    /// }
    /// ```
    pub fn salty_sha384(str: &str, salt_length: u64) -> (String, String){
        let salt = generate_salt(salt_length);
        let encrypted_string = to_sha256(&(salt.to_string() + str));
        return (encrypted_string, salt);
    }

    /// Function, which returns sha-512 salted hash
    /// Salt is added to the beginning of the string
    ///
    /// ##Example
    /// ```
    /// extern crate easy_salt;
    /// use easy_salt::salty_sha::salty_sha512;
    /// 
    /// fn main(){
    ///     let hash = salty_sha512("some string", 6); //first argument is string you need to be hashed, second argument is the salt length
    ///     println!("Hash: {:?}, Salt: {:?}", hash.0, hash.1); //Note, that variable hash is a tuple, so it returns (hash, salt)
    /// }
    /// ```
    pub fn salty_sha512(str: &str, salt_length: u64) -> (String, String){
        let salt = generate_salt(salt_length);
        let encrypted_string = to_sha512(&(salt.to_string() + str));
        return (encrypted_string, salt);
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use salty_sha::*;
    
    //Cannot test private to_sha* functions of the module,
    //This functions were properly tested before they were added to the module
    //This functions were also tested via making them public

    /*#[test]
    fn to_sha1_test() {
        assert_eq!(to_sha1("hello"), "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
    }
    #[test]
    fn to_sha224_test() {
        assert_eq!(to_sha224("hello"), "ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193")
    }
    #[test]
    fn to_sha256_test() {
        assert_eq!(to_sha256("hello"), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
    }
    #[test]
    fn to_sha384_test() {
        assert_eq!(to_sha384("hello"), "59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f")
    }
    #[test]
    fn to_sha512_test() {
        assert_eq!(to_sha512("hello"), "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043")
    }*/
    #[test]
    fn salty_str1_smoke_test() {
        let test = salty_sha1("hello", 2 as u64);
        println!("encrypted string sha1: {:?},\n salt: {:?}", test.0, test.1);
    }
    #[test]
    fn salty_str224_smoke_test() {
        let test = salty_sha224("hello", 2 as u64);
        println!("encrypted string sha224: {:?},\n salt: {:?}", test.0, test.1);
    }
    #[test]
    fn salty_str256_smoke_test() {
        let test = salty_sha256("hello", 2 as u64);
        println!("encrypted string sha256: {:?},\n salt: {:?}", test.0, test.1);
    }
    #[test]
    fn salty_str384_smoke_test() {
        let test = salty_sha384("hello", 2 as u64);
        println!("encrypted string sha384: {:?},\n salt: {:?}", test.0, test.1);
    }
    #[test]
    fn salty_str512_smoke_test() {
        let test = salty_sha512("hello", 2 as u64);
        println!("encrypted string sha512: {:?},\n salt: {:?}", test.0, test.1);
    }
}
