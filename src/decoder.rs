use libc::{c_int, c_long, c_void, pid_t};
pub use syscalls::Sysno;

use crate::syscall::{Address, FileDescriptor, Path, Syscall};

// Import the ptrace function from libc
extern "C" {
    pub fn ptrace(request: c_int, pid: pid_t, addr: *mut c_void, data: *mut c_void) -> c_long;
}

pub fn decode_syscall(syscall_number: i32, pid: pid_t) -> Syscall {
    match Sysno::from(syscall_number) {
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
    }
}

fn read_memory(pid: pid_t, addr: usize) -> c_long {
    unsafe {
        ptrace(
            libc::PTRACE_PEEKDATA.try_into().unwrap(),
            pid,
            addr as *mut c_void,
            std::ptr::null_mut(),
        )
    }
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

fn read_arg0(pid: i32) -> i64 {
    let a0 = unsafe {
        ptrace(
            libc::PTRACE_PEEKUSER.try_into().unwrap(),
            pid,
            (8 * libc::RDI) as *mut c_void,
            std::ptr::null_mut(),
        )
    };
    a0
}

fn read_arg1(pid: i32) -> i64 {
    let a1 = unsafe {
        ptrace(
            libc::PTRACE_PEEKUSER.try_into().unwrap(),
            pid,
            (8 * libc::RSI) as *mut c_void,
            std::ptr::null_mut(),
        )
    };
    a1
}

fn read_arg2(pid: i32) -> i64 {
    let a2 = unsafe {
        ptrace(
            libc::PTRACE_PEEKUSER.try_into().unwrap(),
            pid,
            (8 * libc::RDX) as *mut c_void,
            std::ptr::null_mut(),
        )
    };
    a2
}

fn read_arg3(pid: i32) -> i64 {
    let a3 = unsafe {
        ptrace(
            libc::PTRACE_PEEKUSER.try_into().unwrap(),
            pid,
            (8 * libc::R10) as *mut c_void,
            std::ptr::null_mut(),
        )
    };
    a3
}

fn read_arg4(pid: i32) -> i64 {
    let a4 = unsafe {
        ptrace(
            libc::PTRACE_PEEKUSER.try_into().unwrap(),
            pid,
            (8 * libc::R8) as *mut c_void,
            std::ptr::null_mut(),
        )
    };
    a4
}

fn read_arg5(pid: i32) -> i64 {
    let a5 = unsafe {
        ptrace(
            libc::PTRACE_PEEKUSER.try_into().unwrap(),
            pid,
            (8 * libc::R9) as *mut c_void,
            std::ptr::null_mut(),
        )
    };
    a5
}

fn decode_unknown(syscall_number: Sysno) -> Syscall {
    Syscall::Unknown {
        syscall_number: syscall_number,
    }
}

fn decode_write(pid: i32) -> Syscall {
    let fd = read_arg0(pid);
    let buf_ptr = read_arg1(pid);
    let len = read_arg2(pid);
    let string = read_string(pid, buf_ptr as usize, len as usize);
    Syscall::Write {
        fd: FileDescriptor { fd: fd as i32 },
        buf: Address {
            addr: buf_ptr as usize,
        },
        count: len as usize,
        buf_str: string,
    }
}

fn decode_read(pid: pid_t) -> Syscall {
    let fd = read_arg0(pid);
    let buf_addr = read_arg1(pid);
    let count = read_arg2(pid);

    Syscall::Read {
        fd: FileDescriptor { fd: fd as i32 },
        buf: Address {
            addr: buf_addr as usize,
        },
        count: count as usize,
    }
}

fn decode_openat(pid: pid_t) -> Syscall {
    let dirfd = read_arg0(pid);
    let path_ptr = read_arg1(pid);
    let flags = read_arg2(pid);

    let path = read_string(pid, path_ptr as usize, 256); // Assume maximum path length of 256

    Syscall::OpenAt {
        dirfd: FileDescriptor { fd: dirfd as i32 },
        path: Path { path: path },
        flags: flags as i32,
    }
}

fn decode_close(pid: pid_t) -> Syscall {
    let fd = read_arg0(pid);

    Syscall::Close {
        fd: FileDescriptor { fd: fd as i32 },
    }
}

fn decode_mmap(pid: pid_t) -> Syscall {
    let addr = read_arg0(pid);
    let length = read_arg1(pid);
    let prot = read_arg2(pid);
    let flags = read_arg3(pid);
    let fd = read_arg4(pid);
    let offset = read_arg5(pid);

    Syscall::Mmap {
        addr: Address {
            addr: addr as usize,
        },
        length: length as usize,
        prot: prot as usize,
        flags: flags as usize,
        fd: FileDescriptor { fd: fd as i32 },
        offset: offset as usize,
    }
}

fn decode_brk(pid: pid_t) -> Syscall {
    let addr = read_arg0(pid);
    Syscall::Brk {
        addr: Address {
            addr: addr as usize,
        },
    }
}

fn decode_pread64(pid: pid_t) -> Syscall {
    let fd = read_arg0(pid);
    let buf_ptr = read_arg1(pid);
    let len = read_arg2(pid);
    let offset = read_arg3(pid);

    let buf = read_string(pid, buf_ptr as usize, len as usize);
    Syscall::Pread64 {
        fd: FileDescriptor { fd: fd as i32 },
        buf: Address {
            addr: buf_ptr as usize,
        },
        count: len as usize,
        offset: offset as usize,
        buf_string: buf,
    }
}

fn decode_newfstatat(pid: pid_t) -> Syscall {
    let dirfd = read_arg0(pid);
    let path_ptr = read_arg1(pid);
    let buf_ptr = read_arg2(pid);
    let flag = read_arg3(pid);

    let path = read_string(pid, path_ptr as usize, 256); // Assume max path length of 256
    Syscall::Newfstatat {
        dirfd: FileDescriptor { fd: dirfd as i32 },
        path: Path { path: path },
        buf: Address {
            addr: buf_ptr as usize,
        },
        flag: flag as usize,
    }
}

fn decode_arch_prctl(pid: pid_t) -> Syscall {
    let code = read_arg0(pid);
    let addr = read_arg1(pid);

    Syscall::ArchPrctl {
        code: code as usize,
        addr: Address {
            addr: addr as usize,
        },
    }
}

fn decode_set_tid_address(pid: pid_t) -> Syscall {
    let tidptr = read_arg0(pid);
    Syscall::SetTidAddress {
        tidptr: Address {
            addr: tidptr as usize,
        },
    }
}

fn decode_set_robust_list(pid: pid_t) -> Syscall {
    let head = read_arg0(pid);
    let len = read_arg1(pid);

    Syscall::SetRobustList {
        head: Address {
            addr: head as usize,
        },
        len: len as usize,
    }
}

fn decode_rseq(pid: pid_t) -> Syscall {
    let rseq_ptr = read_arg0(pid);
    let rseq_len = read_arg1(pid);
    let flags = read_arg2(pid);
    let sig = read_arg3(pid);

    Syscall::Rseq {
        rseq_ptr: Address {
            addr: rseq_ptr as usize,
        },
        rseq_len: rseq_len as usize,
        flags: flags as usize,
        sig: sig as usize,
    }
}

fn decode_mprotect(pid: pid_t) -> Syscall {
    let addr = read_arg0(pid);
    let len = read_arg1(pid);
    let prot = read_arg2(pid);

    Syscall::Mprotect {
        addr: Address {
            addr: addr as usize,
        },
        len: len as usize,
        prot: prot as usize,
    }
}

fn decode_prlimit64(pid: pid_t) -> Syscall {
    let pid0 = read_arg0(pid);
    let resource = read_arg1(pid);
    let new_limit_ptr = read_arg2(pid);
    let old_limit_ptr = read_arg3(pid);

    Syscall::Prlimit64 {
        pid: pid0 as usize,
        resource: resource as usize,
        new_limit_ptr: Address {
            addr: new_limit_ptr as usize,
        },
        old_limit_ptr: Address {
            addr: old_limit_ptr as usize,
        },
    }
}

fn decode_munmap(pid: pid_t) -> Syscall {
    let addr = read_arg0(pid);
    let len = read_arg1(pid);

    Syscall::Munmap {
        addr: Address {
            addr: addr as usize,
        },
        len: len as usize,
    }
}

fn decode_getrandom(pid: pid_t) -> Syscall {
    let buf = read_arg0(pid);
    let buflen = read_arg1(pid);
    let flags = read_arg2(pid);

    let random_bytes = read_string(pid, buf as usize, buflen as usize);

    Syscall::Getrandom {
        buf: Address { addr: buf as usize },
        buflen: buflen as usize,
        flags: flags as usize,
        buf_string: random_bytes,
    }
}

fn decode_execve(pid: pid_t) -> Syscall {
    let filename_ptr = read_arg0(pid);
    let argv_ptr = read_arg1(pid);
    let envp_ptr = read_arg2(pid);

    let filename = read_string(pid, filename_ptr as usize, 255);

    Syscall::Execve {
        filename: Path { path: filename },
        argv_ptr: Address {
            addr: argv_ptr as usize,
        },
        envp_ptr: Address {
            addr: envp_ptr as usize,
        },
    }
}

fn decode_access(pid: pid_t) -> Syscall {
    let pathname_ptr = read_arg0(pid);
    let mode = read_arg1(pid);

    let pathname = read_string(pid, pathname_ptr as usize, 255);

    Syscall::Access {
        pathname: Path { path: pathname },
        mode: mode as usize,
    }
}
