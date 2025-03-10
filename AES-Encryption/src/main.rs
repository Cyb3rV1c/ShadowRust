/*
 * Author: Cyb3rV1c
 * Created: 2025
 * License: MIT License
 * This code was written by Cyb3rV1c and is a work in progress for cybersecurity
 * educational purposes.
 */

use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use std::fs;
use std::error::Error;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

fn main() -> Result<(), Box<dyn Error>> {
    // Read the shellcode file (binary)
    let shellcode = fs::read("shellcode.bin")?;
    println!("Read shellcode file, {} bytes", shellcode.len());

    // Define your AES key and IV.
    // IMPORTANT: Replace these example values with your actual 32-byte key and 16-byte IV.
    let key: [u8; 32] = [0x00; 32]; // Example: all zeros (update with your key)
    let iv: [u8; 16]  = [0x00; 16];  // Example: all zeros (update with your IV)

    // Initialize the AES-256 cipher in CBC mode using new_from_slices
    let cipher = Aes256Cbc::new_from_slices(&key, &iv)
        .map_err(|e| format!("Error initializing cipher: {:?}", e))?;

    // Encrypt the shellcode
    let ciphertext = cipher.encrypt_vec(&shellcode);
    println!("Encrypted shellcode, resulting in {} bytes", ciphertext.len());

    // Write the encrypted shellcode to a new file
    fs::write("Data.enc", &ciphertext)?;
    println!("Encrypted shellcode written to shellcode.enc");

    Ok(())
}
