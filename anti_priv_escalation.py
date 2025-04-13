import psutil
import os
import hashlib
import time

# Suspicious binary hashes (add more if needed)
SUSPICIOUS_HASHES = {
    "e99a18c428cb38d5f260853678922e03",  # example MD5 hash
}

def hash_file(path):
    """Return MD5 hash of file if accessible"""
    try:
        with open(path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except Exception:
        return None

def is_suspicious(proc):
    """Check if a process has suspicious traits"""
    try:
        exe = proc.exe()
        uid = proc.uids().real
        hash_val = hash_file(exe)

        if uid == 0 and hash_val in SUSPICIOUS_HASHES:
            print(f"[!] Suspicious root process detected: PID {proc.pid}, EXE: {exe}")
            return True
    except Exception:
        pass
    return False

def main():
    print("[*] Starting privilege escalation detection...")
    known_pids = set(p.pid for p in psutil.process_iter())

    while True:
        time.sleep(2)
        current_pids = set(p.pid for p in psutil.process_iter())

        new_pids = current_pids - known_pids
        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                if is_suspicious(proc):
                    response = input(f"Do you want to terminate PID {pid}? (y/n): ").strip().lower()
                    if response == 'y':
                        proc.terminate()
                        print(f"[+] Process {pid} terminated.")
                    else:
                        print(f"[-] Process {pid} left running.")
            except Exception as e:
                print(f"[!] Error checking process {pid}: {e}")

        known_pids = current_pids

if __name__ == "__main__":
    main()
