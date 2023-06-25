//! # Decoder Module
//!
//! This module contains functions to decode system call numbers into their corresponding Syscall enums.
//! The decoding functions also read the syscall arguments from the traced process. They make extensive use
//! of the `read_arg` and `read_string` helper functions, which read a single argument or a null-terminated string
//! from the traced process, respectively.
//!
//! The decoder functions in this module are designed to be used with the ptrace system call to assist in tracing
//! the system calls made by another process.
use libc::{c_int, c_long, c_void, pid_t};
pub use syscalls::Sysno;

use crate::syscall::{Address, FileDescriptor, Path, Syscall};

// Import the ptrace function from libc library. ptrace is a system call that enables one process 
// (the "tracer") to control another (the "tracee").
extern "C" {
    pub fn ptrace(request: c_int, pid: pid_t, addr: *mut c_void, data: *mut c_void) -> c_long;
}

/// This function receives a system call number and a process ID. It decodes the system call number 
/// into a corresponding system call using a match statement and then calls the appropriate function 
/// to get the details of the system call.
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
        Sysno::lseek => decode_lseek(pid),
        Sysno::ioctl => decode_ioctl(pid),
        Sysno::statfs => decode_statfs(pid),
        Sysno::getdents64 => decode_getdents64(pid),
        Sysno::statx => decode_statx(pid),
        Sysno::lgetxattr => decode_lgetxattr(pid),
        Sysno::getxattr => decode_getxattr(pid),
        Sysno::connect => decode_connect(pid),
        Sysno::socket => decode_socket(pid),
        Sysno::futex => decode_futex(pid),
        Sysno::rt_sigaction => decode_rt_sigaction(pid),
        Sysno::fcntl => decode_fcntl(pid),
        Sysno::readlink => decode_readlink(pid),
        Sysno::sysinfo => decode_sysinfo(pid),
        Sysno::geteuid => decode_geteuid(pid),
        Sysno::socketpair => decode_socketpair(pid),
        Sysno::rt_sigprocmask => decode_rt_sigprocmask(pid),
        Sysno::poll => decode_poll(pid),
        Sysno::clone3 => decode_clone3(pid),
        Sysno::setsockopt => decode_setsockopt(pid),
        Sysno::getpeername => decode_getpeername(pid),
        Sysno::getsockname => decode_getsockname(pid),
        Sysno::sendto => decode_sendto(pid),
        Sysno::recvfrom => decode_recvfrom(pid),
        Sysno::exit_group => decode_exit_group(pid),
        num => decode_unknown(num),
    }
}

/// This function reads a memory location of the traced process. It uses ptrace with PTRACE_PEEKDATA 
/// which reads a word at the address addr in the traced process's memory.
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

/// This function reads a string from the traced process's memory. It reads a word at a time, treats 
/// it as an array of bytes, and adds each byte to the string until it finds a null byte.
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

/// Functions to read syscall arguments. Each syscall has up to six arguments, which are passed in 
/// the registers RDI, RSI, RDX, R10, R8, and R9, respectively. These functions use ptrace with 
/// PTRACE_PEEKUSER which reads a word at the specified offset in the traced process's user area 
/// (the area of kernel memory where values such as registers are saved when signal delivery causes 
/// a switch to kernel mode). The offset for each argument register is given by the corresponding 
/// register's number times the size of a word (8 bytes).
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
        syscall_number: syscall_number as i32,
        syscall_name: format!("{:?}", syscall_number),
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

fn decode_lseek(pid: pid_t) -> Syscall {
    let fd = read_arg0(pid) as i32;
    let offset = read_arg1(pid) as i64;
    let whence = read_arg2(pid) as i32;

    Syscall::Lseek {
        fd: FileDescriptor { fd },
        offset,
        whence,
    }
}

fn decode_ioctl(pid: pid_t) -> Syscall {
    let fd = read_arg0(pid) as i32;
    let request = read_arg1(pid) as usize;
    let argp_addr = read_arg2(pid) as usize;

    Syscall::Ioctl {
        fd: FileDescriptor { fd },
        request,
        argp: Address { addr: argp_addr },
    }
}

fn decode_statfs(pid: pid_t) -> Syscall {
    let path_addr = read_arg0(pid) as usize;
    let buf_addr = read_arg1(pid) as usize;

    let path = read_string(pid, path_addr, 255);

    Syscall::Statfs {
        path: Path { path },
        buf: Address { addr: buf_addr },
    }
}

fn decode_getdents64(pid: pid_t) -> Syscall {
    let fd = read_arg0(pid) as i32;
    let dirp_addr = read_arg1(pid) as usize;
    let count = read_arg2(pid) as usize;

    Syscall::Getdents64 {
        fd: FileDescriptor { fd },
        dirp: Address { addr: dirp_addr },
        count,
    }
}

fn decode_statx(pid: pid_t) -> Syscall {
    let dfd = read_arg0(pid) as i32;
    let pathname_addr = read_arg1(pid) as usize;
    let flags = read_arg2(pid) as i32;
    let mask = read_arg3(pid) as u32;
    let statxbuf_addr = read_arg4(pid) as usize;

    let pathname = read_string(pid, pathname_addr, 255);

    Syscall::Statx {
        dfd: FileDescriptor { fd: dfd },
        pathname: Path { path: pathname },
        flags,
        mask,
        statxbuf: Address {
            addr: statxbuf_addr,
        },
    }
}

fn decode_lgetxattr(pid: pid_t) -> Syscall {
    let pathname_addr = read_arg0(pid) as usize;
    let name_addr = read_arg1(pid) as usize;
    let value_addr = read_arg2(pid) as usize;
    let size = read_arg3(pid) as usize;

    let pathname = read_string(pid, pathname_addr, 255);
    let name = read_string(pid, name_addr, 255);

    Syscall::Lgetxattr {
        pathname: Path { path: pathname },
        name,
        value: Address { addr: value_addr },
        size,
    }
}

fn decode_getxattr(pid: pid_t) -> Syscall {
    let pathname_addr = read_arg0(pid) as usize;
    let name_addr = read_arg1(pid) as usize;
    let value_addr = read_arg2(pid) as usize;
    let size = read_arg3(pid) as usize;

    let pathname = read_string(pid, pathname_addr, 255);
    let name = read_string(pid, name_addr, 255);

    Syscall::Getxattr {
        pathname: Path { path: pathname },
        name,
        value: Address { addr: value_addr },
        size,
    }
}

fn decode_connect(pid: pid_t) -> Syscall {
    let fd = read_arg0(pid) as i32;
    let sockaddr_addr = read_arg1(pid) as usize;
    let addrlen = read_arg2(pid) as usize;

    Syscall::Connect {
        fd: FileDescriptor { fd },
        sockaddr: Address {
            addr: sockaddr_addr,
        },
        addrlen,
    }
}

fn decode_socket(pid: pid_t) -> Syscall {
    let domain = read_arg0(pid) as i32;
    let type_ = read_arg1(pid) as i32;
    let protocol = read_arg2(pid) as i32;

    Syscall::Socket {
        domain,
        type_,
        protocol,
    }
}

fn decode_futex(pid: pid_t) -> Syscall {
    let uaddr = read_arg0(pid) as usize;
    let futex_op = read_arg1(pid) as i32;
    let val = read_arg2(pid) as i32;
    let timeout = read_arg3(pid) as usize;
    let uaddr2 = read_arg4(pid) as usize;
    let val3 = read_arg5(pid) as i32;

    Syscall::Futex {
        uaddr: Address { addr: uaddr },
        futex_op,
        val,
        timeout: Address { addr: timeout },
        uaddr2: Address { addr: uaddr2 },
        val3,
    }
}

fn decode_rt_sigaction(pid: pid_t) -> Syscall {
    let signum = read_arg0(pid) as i32;
    let act_addr = read_arg1(pid) as usize;
    let oldact_addr = read_arg2(pid) as usize;
    let sigsetsize = read_arg3(pid) as usize;

    Syscall::RtSigaction {
        signum,
        act: Address { addr: act_addr },
        oldact: Address { addr: oldact_addr },
        sigsetsize,
    }
}

fn decode_fcntl(pid: pid_t) -> Syscall {
    let fd = read_arg0(pid) as i32;
    let cmd = read_arg1(pid) as i32;
    let arg = read_arg2(pid) as usize;

    Syscall::Fcntl {
        fd: FileDescriptor { fd },
        cmd,
        arg: Address { addr: arg },
    }
}

fn decode_readlink(pid: pid_t) -> Syscall {
    let pathname_addr = read_arg0(pid) as usize;
    let buf_addr = read_arg1(pid) as usize;
    let bufsize = read_arg2(pid) as usize;

    let pathname = read_string(pid, pathname_addr, 255);

    Syscall::Readlink {
        pathname: Path { path: pathname },
        buf: Address { addr: buf_addr },
        bufsize,
    }
}

fn decode_sysinfo(pid: pid_t) -> Syscall {
    let info_addr = read_arg0(pid) as usize;

    Syscall::Sysinfo {
        info: Address { addr: info_addr },
    }
}

fn decode_geteuid(_pid: pid_t) -> Syscall {
    // geteuid has no arguments, so just return the Syscall variant
    Syscall::Geteuid
}

fn decode_socketpair(pid: pid_t) -> Syscall {
    let domain = read_arg0(pid) as i32;
    let socket_type = read_arg1(pid) as i32;
    let protocol = read_arg2(pid) as i32;
    let sv_addr = read_arg3(pid) as usize;

    Syscall::Socketpair {
        domain,
        socket_type,
        protocol,
        sv: Address { addr: sv_addr },
    }
}

fn decode_rt_sigprocmask(pid: pid_t) -> Syscall {
    let how = read_arg0(pid) as i32;
    let set_addr = read_arg1(pid) as usize;
    let oldset_addr = read_arg2(pid) as usize;
    let sigsetsize = read_arg3(pid) as usize;

    Syscall::RtSigprocmask {
        how,
        set: Address { addr: set_addr },
        oldset: Address { addr: oldset_addr },
        sigsetsize,
    }
}

fn decode_poll(pid: pid_t) -> Syscall {
    let fds_addr = read_arg0(pid) as usize;
    let nfds = read_arg1(pid) as usize;
    let timeout = read_arg2(pid) as i32;

    Syscall::Poll {
        fds: Address { addr: fds_addr },
        nfds,
        timeout,
    }
}

fn decode_clone3(pid: pid_t) -> Syscall {
    let cl_args_addr = read_arg0(pid) as usize;
    let size = read_arg1(pid) as usize;

    Syscall::Clone3 {
        cl_args: Address { addr: cl_args_addr },
        size,
    }
}

fn decode_setsockopt(pid: pid_t) -> Syscall {
    let sockfd = read_arg0(pid) as i32;
    let level = read_arg1(pid) as i32;
    let optname = read_arg2(pid) as i32;
    let optval_addr = read_arg3(pid) as usize;
    let optlen = read_arg4(pid) as usize;

    Syscall::Setsockopt {
        sockfd: FileDescriptor { fd: sockfd },
        level,
        optname,
        optval: Address { addr: optval_addr },
        optlen,
    }
}

fn decode_getpeername(pid: pid_t) -> Syscall {
    let sockfd = read_arg0(pid) as i32;
    let addr = read_arg1(pid) as usize;
    let addrlen = read_arg2(pid) as usize;

    Syscall::Getpeername {
        sockfd: FileDescriptor { fd: sockfd },
        addr: Address { addr },
        addrlen: Address { addr: addrlen },
    }
}

fn decode_getsockname(pid: pid_t) -> Syscall {
    let sockfd = read_arg0(pid) as i32;
    let addr = read_arg1(pid) as usize;
    let addrlen = read_arg2(pid) as usize;

    Syscall::Getsockname {
        sockfd: FileDescriptor { fd: sockfd },
        addr: Address { addr },
        addrlen: Address { addr: addrlen },
    }
}

fn decode_sendto(pid: pid_t) -> Syscall {
    let sockfd = read_arg0(pid) as i32;
    let buf = read_arg1(pid) as usize;
    let len = read_arg2(pid) as usize;
    let flags = read_arg3(pid) as i32;
    let dest_addr = read_arg4(pid) as usize;
    let addrlen = read_arg5(pid) as usize;

    Syscall::Sendto {
        sockfd: FileDescriptor { fd: sockfd },
        buf: Address { addr: buf },
        len,
        flags,
        dest_addr: Address { addr: dest_addr },
        addrlen,
    }
}

fn decode_recvfrom(pid: pid_t) -> Syscall {
    let sockfd = read_arg0(pid) as i32;
    let buf = read_arg1(pid) as usize;
    let len = read_arg2(pid) as usize;
    let flags = read_arg3(pid) as i32;
    let src_addr = read_arg4(pid) as usize;
    let addrlen = read_arg5(pid) as usize;

    Syscall::Recvfrom {
        sockfd: FileDescriptor { fd: sockfd },
        buf: Address { addr: buf },
        len,
        flags,
        src_addr: Address { addr: src_addr },
        addrlen: Address { addr: addrlen },
    }
}

fn decode_exit_group(pid: pid_t) -> Syscall {
    let status = read_arg0(pid) as i32;

    Syscall::ExitGroup { status }
}
