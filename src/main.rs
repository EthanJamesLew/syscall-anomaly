//! # Main Module
//!
//! This is the entry point of the application. This module is responsible for parsing command line arguments,
//! launching and attaching the ptrace to the child process, and controlling the main execution loop. The main loop
//! waits for the child process to enter or exit a system call, fetches the syscall number, decodes it into a Syscall
//! enum, and then prints it. In case of syscall interruption, it simply skips to the next syscall.
//! 
//! This module primarily interacts with the `decoder.rs` module for decoding syscall numbers into the Syscall enum.
use clap::{App, Arg};
use libc::{c_int, c_long, pid_t};
use syscalls::Sysno;
use std::ffi::c_void;
use std::fs::File;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::io::{Write, BufReader};

mod decoder;
mod syscall;
mod markov;
use decoder::decode_syscall;

// Define ptrace options
const PTRACE_TRACEME: c_int = 0;
const THRESHOLD: f64 = 0.0001;

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

pub fn write_syscall_numbers_to_file(syscall_numbers: Vec<i32>, filename: &str) -> std::io::Result<()> {
    let mut file = File::create(filename)?;

    let json = serde_json::to_string(&syscall_numbers).unwrap();
    writeln!(file, "{}", json)?;

    Ok(())
}

fn parse_args() -> clap::ArgMatches {
    // Define and return the argument parser
    App::new("PTrace App")
        .arg(
            Arg::with_name("json_files")
                .help("JSON files to load existing syscall data from")
                .required(false)
                .multiple(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("command")
                .help("Command to run and monitor")
                .required(true)
                .last(true)
                .multiple(true)
                .takes_value(true),
        )
        .get_matches()
}

fn load_existing_syscalls(chain: &mut markov::MarkovChain, json_files: &[&str]) {
    // Iterate through each file, read, parse, and add the syscalls to the markov chain
    for json_file in json_files {
        let file = match File::open(json_file) {
            Ok(file) => file,
            Err(_) => {
                eprintln!("Failed to open {}: {}", json_file, std::io::Error::last_os_error());
                continue;
            }
        };
        let reader = BufReader::new(file);
        let syscall_numbers: Vec<i32> = match serde_json::from_reader(reader) {
            Ok(numbers) => numbers,
            Err(_) => {
                eprintln!("Failed to parse JSON from {}", json_file);
                continue;
            }
        };
        chain.add_syscalls(&syscall_numbers);
    }
}

fn monitor_process(chain: &mut markov::MarkovChain, command: &str, args: &[&str]) {
    // Launch process
    let child = unsafe {
        Command::new(command)
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
    let mut is_calling = true;
    let mut last_syscalls: Option<(i32, i32)> = None;
    let mut syscalls: Vec<syscall::Syscall> = Vec::new();
    let mut syscall_numbers: Vec<i32> = Vec::new();

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

        // If entering syscall, decode and push to syscalls
        if is_calling && syscall_number >= 0 {
            let scall = decode_syscall(syscall_number as i32, pid);
            if let Some((last1, last2)) = last_syscalls {
                let probability = chain.transition_probability((last1, last2), syscall_number as i32);
                if probability < THRESHOLD {
                    println!("Anomaly detected: Transition from syscall {:?} to syscall {:?} has low probability: {}", (Sysno::from(last1), Sysno::from(last2)), scall, probability);
                }
            }
            last_syscalls = if let Some((_last1, last2)) = last_syscalls {
                Some((last2, syscall_number as i32))
            } else {
                Some((100, syscall_number as i32))  // Use appropriate default value
            };
            syscalls.push(scall);
            syscall_numbers.push(syscall_number as i32);
        }

        // If exit_group, exit
        if syscall_number == syscalls::Sysno::exit_group as i64 {
            let scall = decode_syscall(syscall_number as i32, pid);
            syscalls.push(scall);
            syscall_numbers.push(syscall_number as i32);
            break;
        }

        // Switch between entering and exiting syscall
        is_calling = !is_calling;

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
    // Write syscall numbers to file
    write_syscall_numbers_to_file(syscall_numbers, "syscall_numbers.json").unwrap();
}

fn main() {
    let matches = parse_args();

    // Get the command and args to run
    let command_args: Vec<&str> = matches.values_of("command").unwrap().collect();
    let (command, args) = command_args.split_at(1);

    // Create a new Markov Chain
    let mut chain = markov::MarkovChain::new();

    // Load existing syscalls
    let json_files: Vec<&str> = matches.values_of("json_files").unwrap_or_default().collect();
    load_existing_syscalls(&mut chain, &json_files);

    // Monitor and analyze the new process
    monitor_process(&mut chain, command[0], args);
}
