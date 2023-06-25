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
    Unknown {
        syscall_number: Sysno,
    },
}
