use syscalls::Sysno;

pub struct Address {
    pub addr: usize,
}

// impl Debug to print addresses in Hex
impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "0x{:x}", self.addr)
    }
}

pub struct Path {
    pub path: String,
}

// impl Debug to print paths in quotes
impl std::fmt::Debug for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "\"{}\"", self.path)
    }
}

#[derive(Debug)]
pub struct FileDescriptor {
    pub fd: i32,
}

#[derive(Debug)]
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
    Unknown {
        syscall_number: Sysno,
    },
}
