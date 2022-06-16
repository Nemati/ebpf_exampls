#!/usr/bin/python3

from __future__ import print_function
from bcc import BPF
from time import sleep
import ctypes as ct

# BPF program
program = """
BPF_HASH(vfs);

int vfs_mkdir_is_called()
{   
    u64 newFileCounter = 0;
    u64 *pointerToVfsMap;

    u64 gtid;
    gtid = bpf_get_current_pid_tgid();
    
    u64 uid;
    uid = bpf_get_current_uid_gid() & 0xFFFFFFF;
    
    pointerToVfsMap = vfs.lookup(&uid);
    
    if (pointerToVfsMap != NULL)
    {
        newFileCounter = *pointerToVfsMap;
    }

    newFileCounter++;
    vfs.update(&uid, &newFileCounter);

    return 0;
}
"""

b = BPF(text=program)
b.attach_kprobe(event="vfs_mkdir", fn_name="vfs_mkdir_is_called")

# header
print("Tracing... Hit Ctrl-C to end.")


while True:
    try:
        sleep(5)
    except KeyboardInterrupt:
        break
    text = ""
    if len(b["vfs"].items()):
        for k,v in b["vfs"].items():
            text += "UsedId {}: number of mkdir:{}\t".format(k.value, v.value)
        print(text)
    else:
        print("No file is being created");

