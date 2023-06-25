use clap::{App, Arg};
use libc::{c_int, c_long, pid_t};
use std::ffi::c_void;
use std::fs::File;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::io::Write;

mod decoder;
mod syscall;
use decoder::decode_syscall;

// Define ptrace options
const PTRACE_TRACEME: c_int = 0;

// Import the ptrace function from libc
extern "C" {
    pub fn ptrace(request: c_int, pid: pid_t, addr: *mut c_void, data: *mut c_void) -> c_long;
}

pub fn write_syscalls_to_file(syscalls: Vec<syscall::Syscall>, filename: &str) -> std::io::Result<()> {
    let mut file = File::create(filename)?;

    for syscall in syscalls {
        let json = serde_json::to_string(&syscall).unwrap();
        writeln!(file, "{}", json)?;
    }

    Ok(())
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

    // collect syscalls
    let mut syscalls: Vec<syscall::Syscall> = Vec::new();

    // Continue to ptrace child process
    loop {
        let wait_status = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        if wait_status == -1 {
            eprintln!("Failed to waitpid: {}", std::io::Error::last_os_error());
            break;
        }

        // Get the syscall number
        let syscall_number = unsafe {
            ptrace(
                libc::PTRACE_PEEKUSER.try_into().unwrap(),
                pid,
                (8 * libc::ORIG_RAX) as *mut c_void,
                std::ptr::null_mut(),
            )
        };
        if syscall_number >= 0 {
            let scall = decode_syscall(syscall_number as i32, pid);
            syscalls.push(scall);
            //println!("{:?}", scall);
        }

        // if exit_group, exit
        if syscall_number == syscalls::Sysno::exit_group as i64 {
            break;
        }

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

    // Write syscalls to file
    write_syscalls_to_file(syscalls, "syscalls.json").unwrap();
}
