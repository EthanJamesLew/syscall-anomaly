use clap::{App, Arg};
use libc::{c_int, c_long, pid_t};
use std::ffi::c_void;
use std::os::unix::process::CommandExt;
use std::process::Command;

mod decoder;
mod syscall;
use decoder::decode_syscall;

// Define ptrace options
const PTRACE_TRACEME: c_int = 0;

// Import the ptrace function from libc
extern "C" {
    pub fn ptrace(request: c_int, pid: pid_t, addr: *mut c_void, data: *mut c_void) -> c_long;
}

fn main() {
    // Parse command line arguments
    let matches = App::new("PTrace App")
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
            //let retval = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::ORIG_RAX) as *mut c_void, std::ptr::null_mut()) };
            //println!("Return: {}", retval);
        } else {
            // Get the syscall number
            let syscall_number = unsafe {
                ptrace(
                    libc::PTRACE_PEEKUSER.try_into().unwrap(),
                    pid,
                    (8 * libc::ORIG_RAX) as *mut c_void,
                    std::ptr::null_mut(),
                )
            };
            let scall = decode_syscall(syscall_number as i32, pid);
            println!("{:?}", scall);
        }

        // Flip the in_syscall flag
        in_syscall = !in_syscall;

        // Tell the process to continue, stopping at the next entrance or exit from a syscall
        unsafe {
            ptrace(
                libc::PTRACE_SYSCALL.try_into().unwrap(),
                pid,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
    }
}
