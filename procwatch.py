#enumerate_processes: collects pid, name, exe, cpu, and memory usage from processes
#detect_ghost_processes: flags processes with no paths from enumerate_processes
#flag_suspicious_paths: flags suspicious paths from enumerate_processes
#flag_network_connections: flags remote network connections from enumerate_processes
#hash_process: generates sha256 hash from individual procs

import psutil
import os
import hashlib

from pkg_resources import non_empty_lines

# ---list of trusted process paths---
TRUSTED_PATHS = [
    "/usr/",
    "/bin/",
    "/sbin/",
    "/System/",
    "/Library/",
    "/Applications/",
    "/private/",
    os.path.expanduser("~/Applications/"), #user specific app folder
]

#---enumerate_processes: collects pid, name, exe, cpu, and memory usage from processes---
def enumerate_processes():
    process_list = [] #empty list for proc results

    for proc in psutil.process_iter(): #collects info from procs
        try: #contingency if cant access
            proc_dict = {
                "pid" : proc.pid,
                "name" : proc.name(),
                "exe" : proc.exe(),
                "cpu" : proc.cpu_percent(),
                "memory_mb" : (proc.memory_info().rss/(1024 * 1024))
            }
            process_list.append(proc_dict) #adds each proc dict to list
        except Exception: continue #skip procs that cant be accessed

    return process_list #brings compiled list back

#---detect_ghost_processes: flags processes with no paths from enumerate_processes---
def detect_ghost_processes(process_list):
    ghost_processes = []

    for proc in process_list:
        exe = proc["exe"]

        if not exe: continue #skip procs with no path

        if not os.path.exists(exe):  # path doesn't exist on disk
            ghost_processes.append(proc)

    return ghost_processes

#---flag_suspicious_paths: flags suspicious paths from enumerate_processes---
def flag_suspicious_paths(process_list):
    suspicious = [] #list of suspicious paths

    for proc in process_list:
        exe = proc["exe"]

        if not exe: continue

        if not any(exe.startswith(path) for path in TRUSTED_PATHS): #checks against trusted paths list
            suspicious.append(proc)

    return suspicious

#---flag_network_connections: flags remote network connections from enumerate_processes---
def flag_network_connections(process_list):
    established_connections = [] #list of connections

    for proc in process_list:
        try: #contigency if no network connection
            connections = psutil.Process(proc["pid"]).connections()
            for conn in connections:
                if conn.status == "ESTABLISHED" and conn.raddr: #checks if established and remote
                    established_connections.append(proc)
                    break
        except Exception: continue

    return established_connections

#---hash_process: generates sha256 hash from individual procs---
def hash_process(proc):
    exe = proc["exe"]

    if not exe: return None

    try:
        sha256 = hashlib.sha256()
        with open(exe, "rb") as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None



#---test block---

# if __name__ == "__main__": #test enumerate_processes
#    processes = enumerate_processes()
#    for p in processes:
#        print(p)

# if __name__ == "__main__": #tests detect_ghost_processes
#   processes = enumerate_processes()
#   ghosts = detect_ghost_processes(processes)
#   print(f"\nGhost processes found: {len(ghosts)}")
#   for p in ghosts:
#       print(p)

# if __name__ == "__main__": #tests flag_suspicious_paths
#     processes = enumerate_processes()
#     suspicious = flag_suspicious_paths(processes)
#     print(f"\nSuspicious paths found: {len(suspicious)}")
#     for p in suspicious:
#         print(p)

# if __name__ == "__main__": #tests flag_network_connections
#     processes = enumerate_processes()
#     network = flag_network_connections(processes)
#     print(f"\nProcesses with established connections: {len(network)}")
#     for p in network:
#         print(p)

# if __name__ == "__main__": #hash_process test block
#     processes = enumerate_processes()
#     test_proc = processes[0]  # grab the first process in the list
#     print(f"Hashing: {test_proc['name']} at {test_proc['exe']}")
#     result = hash_process(test_proc)
#     print(f"SHA-256: {result}")