import psutil
import os

TRUSTED_PATHS = [
    "/usr/",
    "/bin/",
    "/sbin/",
    "/System/",
    "/Library/",
    "/Applications/",
    "/private/",
]

def enumerate_processes():
    process_list = [] #empty list for proc results

    for proc in psutil.process_iter(): #collects info from procs
        try:
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

def detect_ghost_processes(process_list):
    ghost_processes = []

    for proc in process_list:
        exe = proc["exe"]

        if not exe: continue #skip procs with no path

        if not os.path.exists(exe):  # path doesn't exist on disk
            ghost_processes.append(proc)

    return ghost_processes

def flag_suspicious_paths(process_list):
    suspicious = []

    for proc in process_list:
        exe = proc["exe"]

        if not exe: continue

        if not any(exe.startswith(path) for path in TRUSTED_PATHS):
            suspicious.append(proc)

    return suspicious


#test block

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
