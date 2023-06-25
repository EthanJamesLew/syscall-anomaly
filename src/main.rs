use clap::{App, Arg};
use libc::{c_int, c_long, pid_t};
use std::ffi::c_void;
use std::os::unix::process::CommandExt;
use std::process::Command;
use syscalls::*;

// Define ptrace options
const PTRACE_TRACEME: c_int = 0;

// Import the ptrace function from libc
extern "C" {
    pub fn ptrace(request: c_int, pid: pid_t, addr: *mut c_void, data: *mut c_void) -> c_long;
}

fn read_memory(pid: pid_t, addr: usize) -> c_long {
    unsafe { ptrace(libc::PTRACE_PEEKDATA.try_into().unwrap(), pid, addr as *mut c_void, std::ptr::null_mut()) }
}

fn read_string(pid: pid_t, addr: usize, len: usize) -> String {
    let mut s = String::with_capacity(len);
    for i in 0..len {
        let word = read_memory(pid, addr + i * std::mem::size_of::<c_long>());
        let bytes: [u8; 8] = word.to_le_bytes();
        for &byte in bytes.iter() {
            if byte == 0 {
                // Null byte indicates the end of a C string.
                return s;
            } else if byte.is_ascii() {
                // Skip non-ASCII bytes for simplicity.
                s.push(byte as char);
            }
        }
    }
    s
}


fn main() {
    // Parse command line arguments
    let matches = App::new("My Ptrace App")
        .arg(
            Arg::with_name("command")
                .required(true)
                .multiple(true) // Allow multiple values
                .takes_value(true),
        )
        .get_matches();

    // Get the command and args to run
    let command_args: Vec<&str> = matches.values_of("command").unwrap().collect();
    let (command, args) = command_args.split_at(1);

    // Launch process
    let child = unsafe {
        Command::new(command[0])
            .args(args)
            .pre_exec(|| {
                ptrace(
                    PTRACE_TRACEME,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
                Ok(())
            })
            .spawn()
            .expect("Failed to start child process")
    };

    // Get the pid of the child process
    let pid = child.id() as pid_t;

    println!("Attached to process {}", pid);

    // Continue to ptrace child process
    let mut in_syscall = false;
    loop {
        let wait_status = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        if wait_status == -1 {
            eprintln!("Failed to waitpid: {}", std::io::Error::last_os_error());
            break;
        }

        if in_syscall {
            // If we were in a syscall last time, print out the return value now
            let retval = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::ORIG_RAX) as *mut c_void, std::ptr::null_mut()) };
            println!("Return: {}", retval);
        } else {
            // Get the syscall number
            let syscall_number = unsafe {
                ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::ORIG_RAX) as *mut c_void, std::ptr::null_mut())
            };
            match Sysno::from(syscall_number as i32) {
                Sysno::write => decode_write(pid),
                _ => decode_unknown(pid, syscall_number as i32),
            }
        }

        // Flip the in_syscall flag
        in_syscall = !in_syscall;

        // Tell the process to continue, stopping at the next entrance or exit from a syscall
        unsafe { ptrace(libc::PTRACE_SYSCALL.try_into().unwrap(), pid, std::ptr::null_mut(), std::ptr::null_mut()) };
    }
}

fn decode_unknown(pid: i32, syscall_number: i32) {
    println!("Syscall: {}", Sysno::from(syscall_number as i32));
    let registers = ["RDI", "RSI", "RDX", "R10", "R8", "R9"];
    for (idx, &reg) in registers.iter().enumerate() {
        let arg = unsafe {
            ptrace(
                libc::PTRACE_PEEKUSER.try_into().unwrap(),
                pid,
                (8 * libc::ORIG_RAX + ((idx * 8) as i32)) as *mut c_void,
                std::ptr::null_mut()
            )
        };
        println!("Argument {}: {}", reg, arg);
    }
}

fn decode_write(pid: i32) {
    let fd = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDI) as *mut c_void, std::ptr::null_mut()) };
    let buf_ptr = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RSI) as *mut c_void, std::ptr::null_mut()) };
    let len = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDX) as *mut c_void, std::ptr::null_mut()) };
    let string = read_string(pid, buf_ptr as usize, len as usize);
    println!("write({}, \"{}\", {})", fd, string, len);
}
