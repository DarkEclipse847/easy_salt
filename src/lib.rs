use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;

extern crate easy_hasher;
use easy_hasher::easy_hasher::*;

fn generate_salt(length: u64) -> String{
    let salt: String = (0..length)
        .map(|_| thread_rng().sample(Alphanumeric) as char)
        .collect();
    salt
}

fn to_sha256(str: &str) -> String{ 
    let result = sha256(&str.to_string()).to_hex_string();
    result
}

pub fn salty_sha256(str: &str, salt_length: u64) -> (String, String){
    let salt = generate_salt(salt_length);
    let encrypted_string = to_sha256(&(salt.to_string() + str));
    return (encrypted_string, salt);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_sha256_test() {
        assert_eq!(to_sha256("hello"), "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
    }
    #[test]
    fn salty_str_smoke_test() {
        let test = salty_sha256("hello", 2 as u64);
        println!("encrypted string: {:?},\n salt: {:?}", test.0, test.1);
    }
}
