# Syscall Anomaly Detector

 This is a project aimed at exploring anomaly detection of system calls. Just think of it as strace, but with a twist of machine learning.

## What's in it?
Currently, I have developed an strace-like utility that records system calls in a structured format and saves this data to disk. It's not just a passive listener, but an active observer that converts the system calls into a structured format that can be consumed by a machine learning algorithm and used to kill the execution of a child process.

In other words, it's a keen-eyed observer at a masquerade ball, diligently noting down each masked guest's (system call's) unique quirks and eccentricities (parameters and properties) for a mysterious unknown purpose (anomaly detection).

## How to Run It

Running our Syscall Anomaly Detector with no prior syscall trace information is as simple as:

```shell
cargo run -- -- <command>
```

Where <command> is the program you wish to monitor the system calls of.

This will cause the anomaly detector to see everything as an anomaly as it has never seen any of the syscall sequences before. To pass in "nominal" set of traces,
include a json file of syscall integers

```shell
cargo run -- syscall_numbers.json -- <command>
```

The detector will create the `syscall_numbers.json` at the end of every run.
