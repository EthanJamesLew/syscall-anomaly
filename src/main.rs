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

#[derive(Debug)]
pub enum Syscall {
    OpenAt { dirfd: usize, path: String, flags: i32 },
    Close { fd: i32 },
    Read { fd: i32, buf: usize, count: usize },
    Write { fd: i32, buf: usize, count: usize, buf_str: String },
    Mmap { addr: usize, length: usize, prot: usize, flags: usize, fd: usize, offset: usize },
    Brk { addr: usize },
    Pread64 { fd: usize, buf: usize, count: usize, offset: usize, buf_string: String },
    Newfstatat { dirfd: usize, path: String, buf: usize, flag: usize },
    ArchPrctl { code: usize, addr: usize },
    SetTidAddress { tidptr: usize },
    SetRobustList { head: usize, len: usize },
    Rseq { rseq_ptr: usize, rseq_len: usize, flags: usize, sig: usize },
    Mprotect { addr: usize, len: usize, prot: usize },
    Prlimit64 { pid: usize, resource: usize, new_limit_ptr: usize, old_limit_ptr: usize },
    Munmap { addr: usize, len: usize },
    Getrandom { buf: usize, buflen: usize, flags: usize, buf_string: String },
    Execve { filename: String, argv_ptr: usize, envp_ptr: usize },
    Access { pathname: String, mode: usize },
    Unknown { syscall_number: Sysno },
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
            //let retval = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::ORIG_RAX) as *mut c_void, std::ptr::null_mut()) };
            //println!("Return: {}", retval);
        } else {
            // Get the syscall number
            let syscall_number = unsafe {
                ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::ORIG_RAX) as *mut c_void, std::ptr::null_mut())
            };
            let scall = match Sysno::from(syscall_number as i32) {
                Sysno::openat => decode_openat(pid),
                Sysno::close => decode_close(pid),
                Sysno::write => decode_write(pid),
                Sysno::read => decode_read(pid),
                Sysno::mmap => decode_mmap(pid),
                Sysno::brk => decode_brk(pid),
                Sysno::pread64 => decode_pread64(pid),
                Sysno::newfstatat => decode_newfstatat(pid),
                Sysno::arch_prctl => decode_arch_prctl(pid),
                Sysno::set_tid_address => decode_set_tid_address(pid),
                Sysno::set_robust_list => decode_set_robust_list(pid),
                Sysno::rseq => decode_rseq(pid),
                Sysno::mprotect => decode_mprotect(pid),
                Sysno::prlimit64 => decode_prlimit64(pid),
                Sysno::munmap => decode_munmap(pid),
                Sysno::getrandom => decode_getrandom(pid),
                Sysno::execve => decode_execve(pid),
                Sysno::access => decode_access(pid),
                num => decode_unknown(num),
            };

            println!("{:?}", scall);
        }

        // Flip the in_syscall flag
        in_syscall = !in_syscall;

        // Tell the process to continue, stopping at the next entrance or exit from a syscall
        unsafe { ptrace(libc::PTRACE_SYSCALL.try_into().unwrap(), pid, std::ptr::null_mut(), std::ptr::null_mut()) };
    }
}

fn decode_unknown(syscall_number: Sysno) -> Syscall {
    Syscall::Unknown { syscall_number: syscall_number }
}

fn read_arg0(pid: i32) -> i64 {
    let a0 = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDI) as *mut c_void, std::ptr::null_mut()) };
    a0
}

fn read_arg1(pid: i32) -> i64 {
    let a1 = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RSI) as *mut c_void, std::ptr::null_mut()) };
    a1
}

fn read_arg2(pid: i32) -> i64 {
    let a2 = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDX) as *mut c_void, std::ptr::null_mut()) };
    a2
}

fn read_arg3(pid: i32) -> i64 {
    let a3 = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::R10) as *mut c_void, std::ptr::null_mut()) };
    a3
}

fn read_arg4(pid: i32) -> i64 {
    let a4 = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::R8) as *mut c_void, std::ptr::null_mut()) };
    a4
}

fn read_arg5(pid: i32) -> i64 {
    let a5 = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::R9) as *mut c_void, std::ptr::null_mut()) };
    a5
}

fn decode_write(pid: i32) -> Syscall {
    let fd = read_arg0(pid);
    let buf_ptr = read_arg1(pid); 
    let len = read_arg2(pid);
    let string = read_string(pid, buf_ptr as usize, len as usize);
    Syscall::Write { fd: fd as i32, buf: buf_ptr as usize, count: len as usize, buf_str: string }
}

fn decode_read(pid: pid_t) -> Syscall {
    let fd = read_arg0(pid);
    let buf_addr = read_arg1(pid);
    let count = read_arg2(pid);

    Syscall::Read { fd: fd as i32, buf: buf_addr as usize, count: count as usize }
}

fn decode_openat(pid: pid_t) -> Syscall {
    let dirfd = read_arg0(pid);
    let path_ptr = read_arg1(pid);
    let flags = read_arg2(pid);

    let path = read_string(pid, path_ptr as usize, 256); // Assume maximum path length of 256

    Syscall::OpenAt { dirfd: dirfd as usize, path: path, flags: flags as i32 }
}

fn decode_close(pid: pid_t) -> Syscall {
    let fd = read_arg0(pid);

    Syscall::Close { fd: fd as i32 }
}

fn decode_mmap(pid: pid_t) -> Syscall {
    let addr = read_arg0(pid);
    let length = read_arg1(pid);
    let prot = read_arg2(pid);
    let flags = read_arg3(pid);
    let fd = read_arg4(pid);
    let offset = read_arg5(pid);

    Syscall::Mmap { addr: addr as usize, length: length as usize, prot: prot as usize, flags: flags as usize, fd: fd as usize, offset: offset as usize }
}

fn decode_brk(pid: pid_t) -> Syscall {
    let addr = read_arg0(pid);
    Syscall::Brk { addr: addr as usize }
}

fn decode_pread64(pid: pid_t) -> Syscall {
    let fd = read_arg0(pid);
    let buf_ptr = read_arg1(pid);
    let len = read_arg2(pid);
    let offset = read_arg3(pid);

    let buf = read_string(pid, buf_ptr as usize, len as usize);
    Syscall::Pread64 { fd: fd as usize, buf: buf_ptr as usize, count: len as usize, offset: offset as usize, buf_string: buf } 
}

fn decode_newfstatat(pid: pid_t) -> Syscall {
    let dirfd = read_arg0(pid);
    let path_ptr = read_arg1(pid);
    let buf_ptr = read_arg2(pid);
    let flag = read_arg3(pid);

    let path = read_string(pid, path_ptr as usize, 256); // Assume max path length of 256
    Syscall::Newfstatat { dirfd: dirfd as usize, path: path, buf: buf_ptr as usize, flag: flag as usize }
}

fn decode_arch_prctl(pid: pid_t) -> Syscall {
    let code = read_arg0(pid);
    let addr = read_arg1(pid);

    Syscall::ArchPrctl { code: code as usize, addr: addr as usize }
}

fn decode_set_tid_address(pid: pid_t) -> Syscall {
    let tidptr = read_arg0(pid); 
    Syscall::SetTidAddress { tidptr: tidptr as usize }
}

fn decode_set_robust_list(pid: pid_t) -> Syscall {
    let head = read_arg0(pid);
    let len = read_arg1(pid);

    Syscall::SetRobustList { head: head as usize, len: len as usize }
}

fn decode_rseq(pid: pid_t) -> Syscall {
    let rseq_ptr = read_arg0(pid);
    let rseq_len = read_arg1(pid);
    let flags = read_arg2(pid);
    let sig = read_arg3(pid);

    Syscall::Rseq { rseq_ptr: rseq_ptr as usize, rseq_len: rseq_len as usize, flags: flags as usize, sig: sig as usize }
}

fn decode_mprotect(pid: pid_t) -> Syscall {
    let addr = read_arg0(pid);
    let len = read_arg1(pid);
    let prot = read_arg2(pid);

    Syscall::Mprotect { addr: addr as usize, len: len as usize, prot: prot as usize }
}

fn decode_prlimit64(pid: pid_t) -> Syscall {
    let pid0 = read_arg0(pid);
    let resource = read_arg1(pid);
    let new_limit_ptr = read_arg2(pid);
    let old_limit_ptr = read_arg3(pid);

    Syscall::Prlimit64 { pid: pid0 as usize, resource: resource as usize, new_limit_ptr: new_limit_ptr as usize, old_limit_ptr: old_limit_ptr as usize }
}

fn decode_munmap(pid: pid_t) -> Syscall {
    let addr = read_arg0(pid);
    let len = read_arg1(pid);

    Syscall::Munmap { addr: addr as usize, len: len as usize }
}

fn decode_getrandom(pid: pid_t) -> Syscall {
    let buf = read_arg0(pid);
    let buflen = read_arg1(pid);
    let flags = read_arg2(pid);

    let random_bytes = read_string(pid, buf as usize, buflen as usize);

    Syscall::Getrandom { buf: buf as usize, buflen: buflen as usize, flags: flags as usize, buf_string: random_bytes }
}

fn decode_execve(pid: pid_t) -> Syscall {
    let filename_ptr = read_arg0(pid);
    let argv_ptr = read_arg1(pid);
    let envp_ptr = read_arg2(pid);

    let filename = read_string(pid, filename_ptr as usize, 255);
    
    Syscall::Execve { filename: filename, argv_ptr: argv_ptr as usize, envp_ptr: envp_ptr as usize }
}

fn decode_access(pid: pid_t) -> Syscall {
    let pathname_ptr = read_arg0(pid);
    let mode = read_arg1(pid);

    let pathname = read_string(pid, pathname_ptr as usize, 255);
    
    Syscall::Access { pathname: pathname, mode: mode as usize } 
}
