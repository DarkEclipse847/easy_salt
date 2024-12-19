//! This is a simple crate providing salt for commonly used hashing algorithms.
//! This crate will give you opportunity to generate **tuple** of type `(hash, salt)` for your needs.
//!
//! ## List of hashing algorithms
//! - [x] SHA:
//!     - [x] sha-1
//!     - [x] sha-224
//!     - [x] sha-256
//!     - [x] sha-384
//!     - [x] sha-512
//!     - [x] sha3-224
//!     - [x] sha3-256
//!     - [x] sha3-384
//!     - [x] sha3-512
//! - [x] MD:
//!     - [x] md2
//!     - [x] md4
//!     - [x] md5
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
///
///## Example
///
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
///## Example
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
    fn to_sha3_224(str: &str) -> String{ 
        let result = sha3_224(&str.to_string()).to_hex_string();
        result
    }
    fn to_sha3_256(str: &str) -> String{ 
        let result = sha3_256(&str.to_string()).to_hex_string();
        result
    }
    fn to_sha3_384(str: &str) -> String{ 
        let result = sha3_384(&str.to_string()).to_hex_string();
        result
    }
    fn to_sha3_512(str: &str) -> String{ 
        let result = sha3_512(&str.to_string()).to_hex_string();
        result
    }

    /// Function, which returns sha-1 salted hash
    /// Salt is added to the beginning of the string
    ///
    ///## Example
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
    ///## Example
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
    ///## Example
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
    ///## Example
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
        let encrypted_string = to_sha384(&(salt.to_string() + str));
        return (encrypted_string, salt);
    }

    /// Function, which returns sha-512 salted hash
    /// Salt is added to the beginning of the string
    ///
    ///## Example
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
    
    
    /// Generates salted sha3-224 hash
    /// Salt is added to the beginning of the string
    ///
    ///## Example
    /// ```
    /// extern crate easy_salt;
    /// use easy_salt::salty_sha::salty_sha3_224;
    /// 
    /// fn main(){
    ///     let hash = salty_sha3_224("some string", 6); //first argument is string you need to be hashed, second argument is the salt length
    ///     println!("Hash: {:?}, Salt: {:?}", hash.0, hash.1); //Note, that variable hash is a tuple, so it returns (hash, salt)
    /// }
    /// ```
    pub fn salty_sha3_224(str: &str, salt_length: u64) -> (String, String){
        let salt = generate_salt(salt_length);
        let encrypted_string = to_sha3_224(&(salt.to_string() + str));
        return (encrypted_string, salt);
    }
    
    /// Generates salted sha3-256 string
    /// Returns tuple (hash, salt)
    /// Salt is added to the beginning of the string
    ///
    ///## Example
    /// ```
    /// extern crate easy_salt;
    /// use easy_salt::salty_sha::salty_sha3_256;
    /// 
    /// fn main(){
    ///     let hash = salty_sha3_256("some string", 6); //first argument is string you need to be hashed, second argument is the salt length
    ///     println!("Hash: {:?}, Salt: {:?}", hash.0, hash.1); //Note, that variable hash is a tuple, so it returns (hash, salt)
    /// }
    /// ```
    pub fn salty_sha3_256(str: &str, salt_length: u64) -> (String, String){
        let salt = generate_salt(salt_length);
        let encrypted_string = to_sha3_256(&(salt.to_string() + str));
        return (encrypted_string, salt);
    }

    /// Function, which returns sha3-384 salted hash
    /// Salt is added to the beginning of the string
    ///
    ///## Example
    /// ```
    /// extern crate easy_salt;
    /// use easy_salt::salty_sha::salty_sha3_384;
    /// 
    /// fn main(){
    ///     let hash = salty_sha3_384("some string", 6); //first argument is string you need to be hashed, second argument is the salt length
    ///     println!("Hash: {:?}, Salt: {:?}", hash.0, hash.1); //Note, that variable hash is a tuple, so it returns (hash, salt)
    /// }
    /// ```
    pub fn salty_sha3_384(str: &str, salt_length: u64) -> (String, String){
        let salt = generate_salt(salt_length);
        let encrypted_string = to_sha3_384(&(salt.to_string() + str));
        return (encrypted_string, salt);
    }

    /// Function, which returns sha3-512 salted hash
    /// Salt is added to the beginning of the string
    ///
    ///## Example
    /// ```
    /// extern crate easy_salt;
    /// use easy_salt::salty_sha::salty_sha3_512;
    /// 
    /// fn main(){
    ///     let hash = salty_sha3_512("some string", 6); //first argument is string you need to be hashed, second argument is the salt length
    ///     println!("Hash: {:?}, Salt: {:?}", hash.0, hash.1); //Note, that variable hash is a tuple, so it returns (hash, salt)
    /// }
    /// ```
    pub fn salty_sha3_512(str: &str, salt_length: u64) -> (String, String){
        let salt = generate_salt(salt_length);
        let encrypted_string = to_sha3_512(&(salt.to_string() + str));
        return (encrypted_string, salt);
    }
}

/// This module contains MD* hashing algorithms.
/// Althrough this hashing algorithms are vulnerable to different collision attacks and bruteforse, this functions might be helpful to save simple data, or as an example of using different algorithms.
///
///## Example
/// ```
/// extern crate easy_salt;
/// use easy_salt::salty_md::*;
///
/// fn main(){
///     let str: &str = "hello there";
///     let hash = salty_md5(str, 12);
///     let another_hash = salty_md5(str, 12);
///     assert_ne!(hash.0, another_hash.0); //checking for inequality to prove that salt has been added to str
/// }
pub mod salty_md{
    use crate::generate_salt;
    extern crate easy_hasher;
    use easy_hasher::easy_hasher::*;

    fn to_md2(str: &str) -> String{ 
        let result = md2(&str.to_string()).to_hex_string();
        result
    }
    fn to_md4(str: &str) -> String{ 
        let result = md4(&str.to_string()).to_hex_string();
        result
    }
    fn to_md5(str: &str) -> String{ 
        let result = md5(&str.to_string()).to_hex_string();
        result
    }
    
    /// Generates salted md2 string
    /// Returns tuple (hash, salt)
    /// Salt is added to the beginning of the string
    ///
    ///## Example
    /// ```
    /// extern crate easy_salt;
    /// use easy_salt::salty_md::salty_md2;
    /// 
    /// fn main(){
    ///     let hash = salty_md2("some string", 6); //first argument is string you need to be hashed, second argument is the salt length
    ///     println!("Hash: {:?}, Salt: {:?}", hash.0, hash.1); //Note, that variable hash is a tuple, so it returns (hash, salt)
    /// }
    /// ```
    pub fn salty_md2(str: &str, salt_length: u64) -> (String, String){
        let salt = generate_salt(salt_length);
        let encrypted_string = to_md2(&(salt.to_string() + str));
        return (encrypted_string, salt);
    }

    /// Generates salted md4 string
    /// Returns tuple (hash, salt)
    /// Salt is added to the beginning of the string
    ///
    ///## Example
    /// ```
    /// extern crate easy_salt;
    /// use easy_salt::salty_md::salty_md4;
    /// 
    /// fn main(){
    ///     let hash = salty_md4("some string", 6); //first argument is string you need to be hashed, second argument is the salt length
    ///     println!("Hash: {:?}, Salt: {:?}", hash.0, hash.1); //Note, that variable hash is a tuple, so it returns (hash, salt)
    /// }
    /// ```
    pub fn salty_md4(str: &str, salt_length: u64) -> (String, String){
        let salt = generate_salt(salt_length);
        let encrypted_string = to_md4(&(salt.to_string() + str));
        return (encrypted_string, salt);
    }
    
    /// Generates salted md5 string
    /// Returns tuple (hash, salt)
    /// Salt is added to the beginning of the string
    ///
    ///## Example
    /// ```
    /// extern crate easy_salt;
    /// use easy_salt::salty_md::salty_md5;
    /// 
    /// fn main(){
    ///     let hash = salty_md5("some string", 6); //first argument is string you need to be hashed, second argument is the salt length
    ///     println!("Hash: {:?}, Salt: {:?}", hash.0, hash.1); //Note, that variable hash is a tuple, so it returns (hash, salt)
    /// }
    /// ```
    pub fn salty_md5(str: &str, salt_length: u64) -> (String, String){
        let salt = generate_salt(salt_length);
        let encrypted_string = to_md5(&(salt.to_string() + str));
        return (encrypted_string, salt);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use salty_md::*;

    
    #[test]
    fn salty_md2_smoke_test(){
        let hash = salty_md2("hello", 8);
        println!("Hash: {:?}, Salt: {:?}", hash.0, hash.1);
    }
    
    #[test]
    fn salty_md4_smoke_test(){
        let hash = salty_md4("hello", 8);
        println!("Hash: {:?}, Salt: {:?}", hash.0, hash.1);
    }
    
    #[test]
    fn salty_md5_smoke_test(){
        let hash = salty_md5("hello", 8);
        println!("Hash: {:?}, Salt: {:?}", hash.0, hash.1);
    }

    #[test]
    fn salty_md2_assertion(){
        let hash = salty_md2("hello", 16);
        let another_hash = salty_md2("hello", 16);
        assert_ne!(hash.0, another_hash.0);
    }
    #[test]
    fn salty_md4_assertion(){
        let hash = salty_md4("hello", 16);
        let another_hash = salty_md4("hello", 16);
        assert_ne!(hash.0, another_hash.0);
    }
    #[test]
    fn salty_md5_assertion(){
        let hash = salty_md5("hello", 16);
        let another_hash = salty_md5("hello", 16);
        assert_ne!(hash.0, another_hash.0);
    }
}
