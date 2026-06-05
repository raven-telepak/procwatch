# ProcWatch process classification engine
# Takes output from procwatch.py enumeration functions and process_db.py knowledge base.
# Returns ClassifiedProcess dataclass per process with risk label, explanation, kill safety, hash (for unknowns), and path mismatch metadata.

import os
from process_db import NEVER_KILL, KNOWN_PROCESSES
from procwatch import (
    detect_ghost_processes,
    flag_suspicious_paths,
    flag_network_connections,
    hash_process,
)

 #---risk labels---
RISK_SAFE       = "Safe"
RISK_UNKNOWN    = "Unknown"
RISK_SUSPICIOUS = "Suspicious"

#---classify_processes: takes the raw process list from enumerate_processes()
#runs all four detection functions, then classifies each process as SAFE, SUSPICIOUS, or UNKNOWN
#SHA-256 is computed only for UNKNOWN processes as a VirusTotal breadcrumb.
#returns a list of classification dicts, one per process.---
def classify_processes(process_list: list[dict]) -> list[dict]:

    #run all detection passes up front, build PID sets for O(1) lookup
    ghost_pids   = {p["pid"] for p in detect_ghost_processes(process_list)}
    sus_pids     = {p["pid"] for p in flag_suspicious_paths(process_list)}
    network_pids = {p["pid"] for p in flag_network_connections(process_list)}

    results = []

    for proc in process_list:
        pid  = proc.get("pid")
        name = proc.get("name", "")
        exe  = proc.get("exe")

        risk_label   = None
        reason       = None
        safe_to_kill = False
        sha256       = None
        flags        = []

        #---NEVER_KILL check---
        if name in NEVER_KILL:
            risk_label   = RISK_SAFE
            safe_to_kill = False
            reason       = (
                f"{name} is a protected system process. "
                "It cannot be stopped."
            )

        #---KNOWN_PROCESSES check, name AND path must both match---
        elif name in KNOWN_PROCESSES:
            entry    = KNOWN_PROCESSES[name]
            expected = os.path.expanduser(entry["path"])

            if exe and exe.startswith(expected):
                risk_label   = RISK_SAFE
                safe_to_kill = entry["safe_to_kill"]
                reason       = entry["description"]
            else:
                #if name matches but path doesn't, treat as suspicious
                risk_label   = RISK_SUSPICIOUS
                safe_to_kill = False
                flags.append("path_mismatch")
                reason = (
                    f"{name} is a known process but is running from an unexpected location "
                    f"({exe or 'unknown'} instead of {entry['path']}). "
                    "This may indicate impersonation."
                )

        #---Detection flags --> ghost, suspicious path, network---
        elif pid in ghost_pids or pid in sus_pids or pid in network_pids:
            risk_label   = RISK_SUSPICIOUS
            safe_to_kill = False

            if pid in ghost_pids:
                flags.append("ghost")
            if pid in sus_pids:
                flags.append("suspicious_path")
            if pid in network_pids:
                flags.append("network")

            flag_str = ", ".join(flags)
            reason   = (
                f"{name} was flagged during scanning ({flag_str}). "
                "Investigate before taking action."
            )

        #---UNKNOWN (not in DB, not flagged) --> hash as breadcrumb---
        else: #**** need to add way to prompt addition??
            risk_label   = RISK_UNKNOWN
            safe_to_kill = False
            sha256       = hash_process(proc)
            reason       = (
                f"{name} is not in the ProcWatch database. "
                "It may be a legitimate third-party app or background process. "
                "The SHA-256 hash can be used to look it up on VirusTotal."
            )

        results.append({
            "pid":          pid,
            "name":         name,
            "exe":          exe,
            "cpu":          proc.get("cpu", 0.0),
            "memory_mb":    proc.get("memory_mb", 0.0),
            "risk_label":   risk_label,
            "reason":       reason,
            "safe_to_kill": safe_to_kill,
            "flags":        flags,
            "sha256":       sha256,
        })

    return results