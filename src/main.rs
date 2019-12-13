// Vincent Ulitzsch <vincent.ulitzsch@live.de>

pub extern crate generic_array;
extern crate crypto;
use aes_ctr::Aes128Ctr;
use aes_ctr::Aes192Ctr;
use aes_ctr::Aes256Ctr;
use aes_ctr::stream_cipher::generic_array::GenericArray;
use aes_ctr::stream_cipher::{
    NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek
};

use openssl::symm;

//use crypto::aes::{ctr, KeySize};
//use crypto::symmetriccipher::SynchronousStreamCipher;
use crypto::aes;

use std::vec::from_elem;

fn transform_data(key_size: usize,nonce_size: usize, fuzz_data: &[u8])
-> Result<(Vec<u8>,Vec<u8>, Vec<u8>),&'static str>
{
    if fuzz_data.len() < key_size+nonce_size+16 {
        return Err("Fuzz_data too short");
    }
    let key = fuzz_data[0..key_size].to_owned();
    let nonce = fuzz_data[key_size..key_size+nonce_size].to_owned();
    let mut crypto_data = fuzz_data[key_size+nonce_size..].to_owned();
    Ok((key,nonce,crypto_data))

}

macro_rules! generate_aes_call {
    (128,$key_generic:expr,$nonce_generic:expr) => {
        Aes128Ctr::new(&$key_generic, &$nonce_generic);
    };
    /*(192,$key_generic:expr,$nonce_generic:expr) => {
        Aes192Ctr::new(&$key_generic, &$nonce_generic);
    };*/
    (256,$key_generic:expr,$nonce_generic:expr) => {
        Aes256Ctr::new(&$key_generic, &$nonce_generic);
    }
}

macro_rules! generate_aes_openssl {
    (128) => {
        openssl::symm::Cipher::aes_128_ctr();
    };
    /*(192) => {
        openssl::symm::Cipher::aes_192_ctr();
    };*/
    (256) => {
        openssl::symm::Cipher::aes_256_ctr();
    }
}

macro_rules! generate_crypto_aes_call {
    (128,$key:expr,$nonce:expr) => {
        crypto::aes::ctr(crypto::aes::KeySize::KeySize128, $key.as_slice(), $nonce.as_slice());
    };
    (256,$key:expr,$nonce:expr) => {
        crypto::aes::ctr(crypto::aes::KeySize::KeySize256, $key.as_slice(), $nonce.as_slice());
    };
}

macro_rules! generate_aes {
    ($func:ident, $keysize: tt) => (
        fn $func(fuzz_data: &[u8]) {
            let (key, nonce, crypto_data) = match(transform_data(($keysize / 8), 16, fuzz_data)){
                Ok((key,nonce,crypto_data)) => (key,nonce,crypto_data),
                Err(err_str) => {println!("Err: {:?}", err_str); return}
            };
            let original_data = crypto_data.to_owned();
            let mut crypto_data = crypto_data.to_owned();
            let key_generic = GenericArray::from_slice(&key);
            let nonce_generic = GenericArray::from_slice(&nonce);

            let mut cipher = generate_aes_call!($keysize,key_generic,nonce_generic); // Aes128Ctr::new(&key_generic, &nonce_generic);
            // apply keystream (encrypt)
            cipher.apply_keystream(&mut crypto_data);
            //assert_ne!(crypto_data,fuzz_data[(($keysize / 8)+16)..].to_owned());
            println!("Keysize: {:?}", $keysize);
            let openssl_cipher = generate_aes_openssl!($keysize); // openssl::symm::Cipher::aes_128_ctr();
            let ciphertext = openssl::symm::encrypt(
                                openssl_cipher,
                                &key,
                                Some(&nonce),
                                &original_data).unwrap();
            let mut cipher_crypto_aes = generate_crypto_aes_call!($keysize,key,nonce);
            let mut output_crypto_aes: Vec<u8> = vec![0; original_data.len()];
            cipher_crypto_aes.process(&original_data, output_crypto_aes.as_mut_slice());
            println!("Key: {:?}",key);
            println!("Nonce: {:?}", nonce);
            println!("Key generic array: {:?}", key_generic);
            println!("Nonce generic array: {:?}", nonce_generic);
            println!("Data:\naes-ctr: {:?}\nopenssl: {:?}\ncrypto::aes: {:?}\noriginal_text: {:?}",crypto_data,ciphertext,output_crypto_aes,original_data);
            assert_eq!(output_crypto_aes,ciphertext,"Opensll and rust::crypto::aes not equal!");
            assert_eq!(crypto_data,ciphertext, "Openssl and aes_ctr not equal");
            println!("All equal\n");
            // seek to the keystream beginning and apply it again to the `data` (decrypt)
            cipher.seek(0);
            cipher.apply_keystream(&mut crypto_data);
            assert_eq!(crypto_data, original_data, "Decrypted data not equal");
            //println!("Cryto_data: {:?}", crypto_data);
            //println!("Fuzz_data: {:?}", fuzz_data[(($keysize / 8)+16)..].to_owned());
        }
    )
}

generate_aes!(fuzz_aes128, 128);
generate_aes!(fuzz_aes256, 256);

fn fuzz_one_input(fuzz_data: &[u8]){
   if fuzz_data.len() < 2 {
       return
   }
   let option = fuzz_data[0];
   match (option){
       0...128 => fuzz_aes128(&fuzz_data[1..]),
       _ => fuzz_aes256(&fuzz_data[1..])
   };
}

#[macro_use] extern crate honggfuzz;
fn main() -> Result<(), std::io::Error>{
    loop{
        fuzz!(|fuzz_data: &[u8]|{
            fuzz_one_input(fuzz_data);
        });
    };
}

#[cfg(not(fuzzing))]
fn main() -> io::Result<()> {
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;
    let data = buffer.as_bytes();
    fuzz_one_input(data);
    Ok(())
}
