use libc::{pid_t, c_int, c_long};
use std::ffi::c_void;
use clap::{App, Arg};

// Define ptrace options
const PTRACE_TRACEME: c_int = 0;
const PTRACE_SYSCALL: c_int = 24;

// Import the ptrace function from libc
extern "C" {
    pub fn ptrace(
        request: c_int,
        pid: pid_t,
        addr: *mut c_void,
        data: *mut c_void,
    ) -> c_long;
}

fn main() {
    let matches = App::new("syscall-anomaly")
        .version("0.1.0")
        .arg(Arg::with_name("pid")
            .short('p')
            .long("pid")
            .value_name("PID")
            .required(true)
            .takes_value(true))
        .get_matches();

    let pid: pid_t = matches.value_of("pid").unwrap().parse().unwrap();

    let result = unsafe {
        ptrace(PTRACE_TRACEME, pid, std::ptr::null_mut(), std::ptr::null_mut())
    };
    
    if result < 0 {
        println!("Failed to attach to process");
    } else {
        println!("Attached to process {}", pid);
        loop {
            let syscall = unsafe {
                ptrace(PTRACE_SYSCALL, pid as i32, std::ptr::null_mut(), std::ptr::null_mut())
            };
            if syscall < 0 {
                println!("Failed to get syscall");
                break;
            } else {
                // Here you would do something with the syscall, like sending it to
                // the pattern detection component of your program
                println!("Syscall: {}", syscall);
            }
        }
    }
}
