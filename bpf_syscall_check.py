#!/usr/bin/python3

from __future__ import print_function
from bcc import BPF
from time import sleep

# BPF program
program = """
int bpf_syscall_is_called()
{
    u64 pid;
    pid = bpf_get_current_pid_tgid();

    bpf_trace_printk("bpf syscall is here! %d \\n", pid);

    return 0;
}
"""

b = BPF(text=program)
bpf_syscall_event = b.get_syscall_fnname("bpf")
b.attach_kprobe(event=bpf_syscall_event, fn_name="bpf_syscall_is_called")
b.trace_print();
# header
print("Tracing... Hit Ctrl-C to end.")

