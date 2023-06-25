//! # Syscall Module
//!
//! This module defines the `Syscall` enum, which represents a system call and its arguments.
//! Each variant of the `Syscall` enum corresponds to a different system call. The enum variants carry all
//! the relevant information about the system call as parameters.
//!
//! This module also defines the helper structs `Address`, `Path`, and `FileDescriptor` used in the `Syscall`
//! enum. These helper structs serve to increase code readability and maintainability.
//!
//! This `Syscall` enum is the primary data type used to represent system calls throughout the application.
use serde::{Deserialize, Serialize};

/// Represents a memory address. 
/// It's serializable/deserializable for easy storage and retrieval.
#[derive(Serialize, Deserialize)]
pub struct Address {
    pub addr: usize,
}

// Implement Debug trait to allow for custom output formatting for Address
impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "0x{:x}", self.addr)
    }
}

/// Represents a filesystem path. 
/// It's serializable/deserializable for easy storage and retrieval.
#[derive(Serialize, Deserialize)]
pub struct Path {
    pub path: String,
}

// Implement Debug trait to allow for custom output formatting for Path
impl std::fmt::Debug for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "\"{}\"", self.path)
    }
}

/// Represents a file descriptor. 
/// It's serializable/deserializable and debug-printable out of the box.
#[derive(Serialize, Deserialize, Debug)]
pub struct FileDescriptor {
    pub fd: i32,
}

/// Enum representing different types of system calls. 
/// Each variant of the enum represents a specific system call and the parameters it uses.
#[derive(Serialize, Deserialize, Debug)]

pub enum Syscall {
    OpenAt {
        dirfd: FileDescriptor,
        path: Path,
        flags: i32,
    },
    Close {
        fd: FileDescriptor,
    },
    Read {
        fd: FileDescriptor,
        buf: Address,
        count: usize,
    },
    Write {
        fd: FileDescriptor,
        buf: Address,
        count: usize,
        buf_str: String,
    },
    Mmap {
        addr: Address,
        length: usize,
        prot: usize,
        flags: usize,
        fd: FileDescriptor,
        offset: usize,
    },
    Brk {
        addr: Address,
    },
    Pread64 {
        fd: FileDescriptor,
        buf: Address,
        count: usize,
        offset: usize,
        buf_string: String,
    },
    Newfstatat {
        dirfd: FileDescriptor,
        path: Path,
        buf: Address,
        flag: usize,
    },
    ArchPrctl {
        code: usize,
        addr: Address,
    },
    SetTidAddress {
        tidptr: Address,
    },
    SetRobustList {
        head: Address,
        len: usize,
    },
    Rseq {
        rseq_ptr: Address,
        rseq_len: usize,
        flags: usize,
        sig: usize,
    },
    Mprotect {
        addr: Address,
        len: usize,
        prot: usize,
    },
    Prlimit64 {
        pid: usize,
        resource: usize,
        new_limit_ptr: Address,
        old_limit_ptr: Address,
    },
    Munmap {
        addr: Address,
        len: usize,
    },
    Getrandom {
        buf: Address,
        buflen: usize,
        flags: usize,
        buf_string: String,
    },
    Execve {
        filename: Path,
        argv_ptr: Address,
        envp_ptr: Address,
    },
    Access {
        pathname: Path,
        mode: usize,
    },
    Lseek {
        fd: FileDescriptor,
        offset: i64,
        whence: i32,
    },
    Ioctl {
        fd: FileDescriptor,
        request: usize,
        argp: Address,
    },
    Statfs {
        path: Path,
        buf: Address,
    },
    Getdents64 {
        fd: FileDescriptor,
        dirp: Address,
        count: usize,
    },
    Statx {
        dfd: FileDescriptor,
        pathname: Path,
        flags: i32,
        mask: u32,
        statxbuf: Address,
    },
    Lgetxattr {
        pathname: Path,
        name: String,
        value: Address,
        size: usize,
    },
    Getxattr {
        pathname: Path,
        name: String,
        value: Address,
        size: usize,
    },
    Connect {
        fd: FileDescriptor,
        sockaddr: Address,
        addrlen: usize,
    },
    Socket {
        domain: i32,
        type_: i32,
        protocol: i32,
    },
    Futex {
        uaddr: Address,
        futex_op: i32,
        val: i32,
        timeout: Address,
        uaddr2: Address,
        val3: i32,
    },
    RtSigaction {
        signum: i32,
        act: Address,
        oldact: Address,
        sigsetsize: usize,
    },
    Fcntl {
        fd: FileDescriptor,
        cmd: i32,
        arg: Address,
    },
    Readlink {
        pathname: Path,
        buf: Address,
        bufsize: usize,
    },
    Sysinfo {
        info: Address,
    },
    Geteuid,
    Socketpair {
        domain: i32,
        socket_type: i32,
        protocol: i32,
        sv: Address,
    },
    RtSigprocmask {
        how: i32,
        set: Address,
        oldset: Address,
        sigsetsize: usize,
    },
    Poll {
        fds: Address,
        nfds: usize,
        timeout: i32,
    },
    Clone3 {
        cl_args: Address,
        size: usize,
    },
    Setsockopt {
        sockfd: FileDescriptor,
        level: i32,
        optname: i32,
        optval: Address,
        optlen: usize,
    },
    Getpeername {
        sockfd: FileDescriptor,
        addr: Address,
        addrlen: Address,
    },
    Getsockname {
        sockfd: FileDescriptor,
        addr: Address,
        addrlen: Address,
    },
    Sendto {
        sockfd: FileDescriptor,
        buf: Address,
        len: usize,
        flags: i32,
        dest_addr: Address,
        addrlen: usize,
    },
    Recvfrom {
        sockfd: FileDescriptor,
        buf: Address,
        len: usize,
        flags: i32,
        src_addr: Address,
        addrlen: Address,
    },
    ExitGroup {
        status: i32,
    },
    Unknown {
        syscall_number: i32,
        syscall_name: String,
    },
}
