# easy_salt 0.2.0

This is a simple crate providing salt for commonly used hashing algorithms.
This crate will give you opportunity to generate **tuple** of type `(hash, salt)` for your needs.

`All of the code was written on Android phone using Termux. :)`

## List of hashing algorithms
Unchecked algorithms will be added soon
 - [x] SHA:
     - [x] sha-1
     - [x] sha-224
     - [x] sha-256
     - [x] sha-384
     - [x] sha-512
     - [x] sha3-224
     - [x] sha3-256
     - [x] sha3-384
     - [x] sha3-512
 - [x] MD:
     - [x] md2
     - [x] md4
     - [x] md5
 - [ ] Bcrypt
 - [ ] Argon2:
     - [ ] Argon2d
     - [ ] Argon2i
     - [ ] Argon2id

## Example
 ```
 extern crate easy_salt;
 use easy_salt::salty_sha::*;

 fn main(){
     let length: u64 = 8;
     let hash = salty_sha256("hello", length);
     println!("Hash: {:?}, Salt: {:?}", hash.0, hash.1);

     let another_hash = salty_sha256("hello", length);
     println!("Second Hash: {:?}, Second salt: {:?}", another_hash.0, another_hash.1);

     assert_ne!(hash.0, another_hash.0);
 }
 ```

There is a plan to change logic so instead of tuple functions will return struct with fields `hash` and `salt` respectfully for better readability.
