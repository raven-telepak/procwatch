from process_db import KNOWN_PROCESSES
from classifier import RISK_SAFE, RISK_SUSPICIOUS, RISK_UNKNOWN

FLAG_MESSAGES = {
    "ghost":            "This process is running but its file no longer exists on disk. The original application may have been deleted or moved while it was still active.",
    "suspicious_path":  "This is running from an unusual location. Legitimate system processes run from specific folders; programs found outside those folders are worth a closer look.",
    "network":          "This process has an active outbound connection. It's currently communicating with a remote server, and it's not clear what data it may be sending.",
    "path_mismatch":    "This doesn't usually run from this location. It may have been tampered with or could be impersonating a known system process.",
}

def translate_process(classified_proc: dict) -> str:
    name       = classified_proc["name"]
    risk_label = classified_proc["risk_label"]
    flags      = classified_proc["flags"]
    sha256     = classified_proc["sha256"]
    exe        = classified_proc["exe"] or "unknown location"

    if risk_label == RISK_SAFE:
        if name in KNOWN_PROCESSES:
            return KNOWN_PROCESSES[name]["description"]
        return "This is a protected system process. It cannot be stopped."

    elif risk_label == RISK_SUSPICIOUS:
        sentences = [FLAG_MESSAGES[flag] for flag in flags if flag in FLAG_MESSAGES]
        sentences.append("This process should be looked in to before any action is taken.")
        return " ".join(sentences)


    elif risk_label == RISK_UNKNOWN:
        message = f"{name} is not in the ProcessWatch database. It is running from {exe}."
        if sha256 is not None:
            message += " This process has a unique identifier (SHA-256 hash) that can be looked up on VirusTotal to check whether it is known or potentially malicious."
        return message