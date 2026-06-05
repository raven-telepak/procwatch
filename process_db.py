# ProcWatch process knowledge base
# NEVER_KILL: hardcoded set checked at kill function level, not just UI
# KNOWN_PROCESSES: keyed by process name; trust based on name AND path, never name alone

# -------------------------------------------------------------------------
# NO KILL LIST --> these should not be touched under any circumstances
# Killing these could cause irreversible damage to your machine, and may require complete reimaging
# -------------------------------------------------------------------------
NEVER_KILL = {
    # Core OS / kernel
    "kernel_task",
    "launchd",
    "loginwindow",
    "WindowServer",
    # Logging & configuration
    "syslogd",
    "configd",
    "notifyd",
    # Storage & power
    "diskarbitrationd",
    "powerd",
    # Audio & directory services
    "coreaudiod",
    "opendirectoryd",
}

KNOWN_PROCESSES = {

# -------------------------------------------------------------------------
# SAFE TO KILL --> background analysis, media indexing, optional features
# These will restart automatically; stopping them is low-risk
# -------------------------------------------------------------------------

    "photoanalysisd": {
        "path": "/usr/libexec/",
        "description": "Analyzes your photo library for faces and scenes. Safe to stop; will restart automatically.",
        "safe_to_kill": True,
    },
    "photolibraryd": {
        "path": "/usr/libexec/",
        "description": "Indexes your photo library. Can use significant CPU during large imports.",
        "safe_to_kill": True,
    },
    "mediaanalysisd": {
        "path": "/usr/libexec/",
        "description": "Analyzes media files for metadata and thumbnails. High CPU during bulk imports.",
        "safe_to_kill": True,
    },
    "photostream": {
        "path": "/System/Library/PrivateFrameworks/PhotoStream.framework/",
        "description": "Syncs photos to iCloud Photo Stream. Stopping it pauses iCloud photo uploads temporarily.",
        "safe_to_kill": True,
    },
    "bookstoreagent": {
        "path": "/System/Library/PrivateFrameworks/BookKit.framework/",
        "description": "Handles Apple Books store updates in the background. No impact on active apps if stopped.",
        "safe_to_kill": True,
    },
    "parsec-fbf": {
        "path": "/usr/libexec/",
        "description": "Feedback assistant data collection. Non-essential background reporter.",
        "safe_to_kill": True,
    },
    "photolibraryanalysis": {
        "path": "/usr/libexec/",
        "description": "Secondary photo library analysis pass. Safe to stop; restarts on next login.",
        "safe_to_kill": True,
    },
    "memories": {
        "path": "/System/Library/PrivateFrameworks/",
        "description": "Compiles photo memories slideshows. CPU-intensive; safe to terminate.",
        "safe_to_kill": True,
    },
    #Misc

# -------------------------------------------------------------------------
# NOT SAFE TO KILL --> system integrity, security, networking, user session
# Stopping these can cause instability, data loss, or broken system features.
# -------------------------------------------------------------------------

    # Search & indexing
    "mds": {
        "path": "/System/Library/Frameworks/CoreServices.framework/",
        "description": "Spotlight metadata server. Stopping it breaks Spotlight search system-wide.",
        "safe_to_kill": False,
    },
    "mds_stores": {
        "path": "/System/Library/Frameworks/CoreServices.framework/",
        "description": "Stores Spotlight search index data. Core component of the search pipeline.",
        "safe_to_kill": False,
    },
    "mdworker": {
        "path": "/System/Library/Frameworks/CoreServices.framework/",
        "description": "Spotlight worker that indexes individual files. Spawns multiple instances during indexing.",
        "safe_to_kill": False,
    },
    "mdworker_shared": {
        "path": "/System/Library/Frameworks/CoreServices.framework/",
        "description": "Shared Spotlight indexing worker. Part of the core search subsystem.",
        "safe_to_kill": False,
    },
    "corespotlightd": {
        "path": "/System/Library/CoreServices/",
        "description": "Manages the Spotlight search index. Required for app and file search to work.",
        "safe_to_kill": False,
    },

    # Security & certificates
    "trustd": {
        "path": "/usr/libexec/",
        "description": "Manages certificate trust and TLS validation. Stopping it can break HTTPS connections.",
        "safe_to_kill": False,
    },
    "secd": {
        "path": "/usr/libexec/",
        "description": "Keychain security daemon. Handles credential storage and retrieval for all apps.",
        "safe_to_kill": False,
    },
    "securityd": {
        "path": "/usr/libexec/",
        "description": "Core system security daemon. Manages authorization and cryptographic services.",
        "safe_to_kill": False,
    },

    # Networking & preferences
    "nsurlsessiond": {
        "path": "/usr/libexec/",
        "description": "Manages background network downloads for apps. Stopping it interrupts pending transfers.",
        "safe_to_kill": False,
    },
    "cfprefsd": {
        "path": "/usr/libexec/",
        "description": "Preferences daemon. Reads and writes app settings; stopping it can corrupt preferences.",
        "safe_to_kill": False,
    },

    # IPC & notifications
    "distnoted": {
        "path": "/usr/sbin/",
        "description": "Distributed notifications daemon. Coordinates inter-process events across the system.",
        "safe_to_kill": False,
    },
    "UserEventAgent": {
        "path": "/usr/libexec/",
        "description": "Monitors user-level system events (login items, USB, calendar). Core session daemon.",
        "safe_to_kill": False,
    },

    # Continuity & wireless
    "rapportd": {
        "path": "/usr/libexec/",
        "description": "Powers Handoff, AirDrop, and iPhone continuity features between Apple devices.",
        "safe_to_kill": False,
    },
    "wirelessproxd": {
        "path": "/usr/libexec/",
        "description": "Manages wireless proximity detection for Handoff and AirDrop. Part of continuity stack.",
        "safe_to_kill": False,
    },
    "bluetoothd": {
        "path": "/usr/sbin/",
        "description": "Core Bluetooth daemon. Stopping it kills all Bluetooth devices including keyboard and mouse.",
        "safe_to_kill": False,
    },

    # Speech & audio
    "corespeechd": {
        "path": "/usr/libexec/",
        "description": "Speech recognition engine used by Siri and dictation. Non-critical but affects voice features.",
        "safe_to_kill": False,
    },

    # UI / UX
    "PowerChime": {
        "path": "/System/Library/CoreServices/",
        "description": "Plays the charging connection sound. Cosmetic; system-managed and low priority.",
        "safe_to_kill": False,
    },

    # Misc

# -------------------------------------------------------------------------
# COMMON THIRD-PARTY --> well-known apps, conservative defaults
# -------------------------------------------------------------------------

    "Spotify": {
        "path": "/Applications/Spotify.app/",
        "description": "Spotify music streaming client.",
        "safe_to_kill": True,
    },
    "Google Chrome": {
        "path": "/Applications/Google Chrome.app/",
        "description": "Google Chrome browser. Closing it will terminate all open tabs.",
        "safe_to_kill": True,
    },
    "firefox": {
        "path": "/Applications/Firefox.app/",
        "description": "Mozilla Firefox browser. Closing it will terminate all open tabs.",
        "safe_to_kill": True,
    },
    "Slack": {
        "path": "/Applications/Slack.app/",
        "description": "Slack messaging client. Safe to close; messages sync on next launch.",
        "safe_to_kill": True,
    },
    "zoom.us": {
        "path": "/Applications/zoom.us.app/",
        "description": "Zoom video conferencing. Stopping it ends any active calls.",
        "safe_to_kill": True,
    },
    "Discord": {
        "path": "/Applications/Discord.app/",
        "description": "Discord voice and text chat client.",
        "safe_to_kill": True,
    },
    "iTerm2": {
        "path": "/Applications/iTerm.app/",
        "description": "iTerm2 terminal emulator.",
        "safe_to_kill": True,
    },
    "Terminal": {
        "path": "/System/Applications/Utilities/Terminal.app/",
        "description": "macOS built-in terminal. Closing it ends any running shell sessions.",
        "safe_to_kill": True,
    },
    "Code Helper": {
        "path": "/Applications/Visual Studio Code.app/",
        "description": "VS Code renderer/extension host process. Part of the VS Code process tree.",
        "safe_to_kill": True,
    },
}