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
            //println!("Return: {}", retval);
        } else {
            // Get the syscall number
            let syscall_number = unsafe {
                ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::ORIG_RAX) as *mut c_void, std::ptr::null_mut())
            };
            match Sysno::from(syscall_number as i32) {
                Sysno::write => decode_write(pid),
                Sysno::read => decode_read(pid),
                Sysno::openat => decode_openat(pid),
                Sysno::mmap => decode_mmap(pid),
                Sysno::brk => decode_brk(pid),
                Sysno::close => decode_close(pid),
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
    println!("UNKNOWN Syscall: {}", Sysno::from(syscall_number as i32));
    //let registers = ["RDI", "RSI", "RDX", "R10", "R8", "R9"];
    //for (idx, &reg) in registers.iter().enumerate() {
    //    let arg = unsafe {
    //        ptrace(
    //            libc::PTRACE_PEEKUSER.try_into().unwrap(),
    //            pid,
    //            (8 * libc::ORIG_RAX + ((idx * 8) as i32)) as *mut c_void,
    //            std::ptr::null_mut()
    //        )
    //    };
    //    println!("Argument {}: {}", reg, arg);
    //}
}

fn decode_write(pid: i32) {
    let fd = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDI) as *mut c_void, std::ptr::null_mut()) };
    let buf_ptr = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RSI) as *mut c_void, std::ptr::null_mut()) };
    let len = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDX) as *mut c_void, std::ptr::null_mut()) };
    let string = read_string(pid, buf_ptr as usize, len as usize);
    println!("write({}, \"{}\", {})", fd, string, len);
}

fn decode_read(pid: pid_t) {
    let fd = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDI) as *mut c_void, std::ptr::null_mut()) };
    let buf_addr = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RSI) as *mut c_void, std::ptr::null_mut()) };
    let count = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDX) as *mut c_void, std::ptr::null_mut()) };

    println!("read({}, {:p}, {})", fd, buf_addr as *const c_void, count);

    let res = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RAX) as *mut c_void, std::ptr::null_mut()) } as isize;
    if res >= 0 {
        // If the read was successful, we can also print the buffer contents.
        let buf = read_string(pid, buf_addr as usize, res as usize);
        println!(" = {} \"{}\"", res, buf);
    } else {
        // If the read failed, just print the error number.
        println!(" = -1 ERRNO={}", -res);
    }
}

fn decode_openat(pid: pid_t) {
    let dirfd = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDI) as *mut c_void, std::ptr::null_mut()) };
    let path_ptr = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RSI) as *mut c_void, std::ptr::null_mut()) };
    let flags = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDX) as *mut c_void, std::ptr::null_mut()) };
    let path = read_string(pid, path_ptr as usize, 256); // Assume maximum path length of 256

    println!("openat({}, \"{}\", {})", dirfd, path, flags);
}

fn decode_mmap(pid: pid_t) {
    let addr = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDI) as *mut c_void, std::ptr::null_mut()) };
    let length = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RSI) as *mut c_void, std::ptr::null_mut()) };
    let prot = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDX) as *mut c_void, std::ptr::null_mut()) };
    let flags = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::R10) as *mut c_void, std::ptr::null_mut()) };
    let fd = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::R8) as *mut c_void, std::ptr::null_mut()) };
    let offset = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::R9) as *mut c_void, std::ptr::null_mut()) };

    println!("mmap({:p}, {}, {}, {}, {}, {})", addr as *const c_void, length, prot, flags, fd, offset);
}

fn decode_brk(pid: pid_t) {
    let addr = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDI) as *mut c_void, std::ptr::null_mut()) };

    println!("brk({:p})", addr as *const c_void);
}

fn decode_close(pid: pid_t) {
    let fd = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDI) as *mut c_void, std::ptr::null_mut()) };

    println!("close({})", fd);
}

fn decode_pread64(pid: pid_t) {
    let fd = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDI) as *mut c_void, std::ptr::null_mut()) };
    let buf_ptr = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RSI) as *mut c_void, std::ptr::null_mut()) };
    let len = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDX) as *mut c_void, std::ptr::null_mut()) };
    let offset = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::R10) as *mut c_void, std::ptr::null_mut()) };

    let buf = read_string(pid, buf_ptr as usize, len as usize);
    println!("pread64({}, \"{}\", {}, {})", fd, buf, len, offset);
}

fn decode_newfstatat(pid: pid_t) {
    let dirfd = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDI) as *mut c_void, std::ptr::null_mut()) };
    let path_ptr = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RSI) as *mut c_void, std::ptr::null_mut()) };
    let buf_ptr = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDX) as *mut c_void, std::ptr::null_mut()) };
    let flag = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::R10) as *mut c_void, std::ptr::null_mut()) };

    let path = read_string(pid, path_ptr as usize, 256); // Assume max path length of 256
    println!("newfstatat({}, \"{}\", {:p}, {})", dirfd, path, buf_ptr as *const c_void, flag);
}

fn decode_arch_prctl(pid: pid_t) {
    let code = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDI) as *mut c_void, std::ptr::null_mut()) };
    let addr = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RSI) as *mut c_void, std::ptr::null_mut()) };

    println!("arch_prctl({}, {:p})", code, addr as *const c_void);
}

fn decode_set_tid_address(pid: pid_t) {
    let tidptr = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDI) as *mut c_void, std::ptr::null_mut()) };

    println!("set_tid_address({:p})", tidptr as *const c_void);
}

fn decode_set_robust_list(pid: pid_t) {
    let head = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDI) as *mut c_void, std::ptr::null_mut()) };
    let len = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RSI) as *mut c_void, std::ptr::null_mut()) };

    println!("set_robust_list({:p}, {})", head as *const c_void, len);
}

fn decode_rseq(pid: pid_t) {
    let rseq_ptr = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDI) as *mut c_void, std::ptr::null_mut()) };
    let rseq_len = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RSI) as *mut c_void, std::ptr::null_mut()) };
    let flags = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDX) as *mut c_void, std::ptr::null_mut()) };
    let sig = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::R10) as *mut c_void, std::ptr::null_mut()) };

    println!("rseq({:p}, {}, {}, {})", rseq_ptr as *const c_void, rseq_len, flags, sig);
}

fn decode_mprotect(pid: pid_t) {
    let addr = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDI) as *mut c_void, std::ptr::null_mut()) };
    let len = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RSI) as *mut c_void, std::ptr::null_mut()) };
    let prot = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDX) as *mut c_void, std::ptr::null_mut()) };

    println!("mprotect({:p}, {}, {})", addr as *const c_void, len, prot);
}

fn decode_prlimit64(pid: pid_t) {
    let pid = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDI) as *mut c_void, std::ptr::null_mut()) };
    let resource = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid as i32, (8 * libc::RSI) as *mut c_void, std::ptr::null_mut()) };
    let new_limit_ptr = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid as i32, (8 * libc::RDX) as *mut c_void, std::ptr::null_mut()) };
    let old_limit_ptr = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid as i32, (8 * libc::R10) as *mut c_void, std::ptr::null_mut()) };

    println!("prlimit64({}, {}, {:p}, {:p})", pid, resource, new_limit_ptr as *const c_void, old_limit_ptr as *const c_void);
}

fn decode_munmap(pid: pid_t) {
    let addr = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDI) as *mut c_void, std::ptr::null_mut()) };
    let len = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RSI) as *mut c_void, std::ptr::null_mut()) };

    println!("munmap({:p}, {})", addr as *const c_void, len);
}

fn decode_getrandom(pid: pid_t) {
    let buf = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDI) as *mut c_void, std::ptr::null_mut()) };
    let buflen = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RSI) as *mut c_void, std::ptr::null_mut()) };
    let flags = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDX) as *mut c_void, std::ptr::null_mut()) };

    let random_bytes = read_string(pid, buf as usize, buflen as usize);
    println!("getrandom(\"{}\", {}, {})", random_bytes, buflen, flags);
}

fn decode_execve(pid: pid_t) {
    let filename_ptr = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDI) as *mut c_void, std::ptr::null_mut()) };
    let argv_ptr = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RSI) as *mut c_void, std::ptr::null_mut()) };
    let envp_ptr = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDX) as *mut c_void, std::ptr::null_mut()) };

    let filename = read_string(pid, filename_ptr as usize, 255);
    
    println!("execve(\"{}\", {:p}, {:p})", filename, argv_ptr as *const c_void, envp_ptr as *const c_void);
}

fn decode_access(pid: pid_t) {
    let pathname_ptr = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RDI) as *mut c_void, std::ptr::null_mut()) };
    let mode = unsafe { ptrace(libc::PTRACE_PEEKUSER.try_into().unwrap(), pid, (8 * libc::RSI) as *mut c_void, std::ptr::null_mut()) };

    let pathname = read_string(pid, pathname_ptr as usize, 255);
    
    println!("access(\"{}\", {})", pathname, mode);
}
