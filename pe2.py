import psutil
import os
import time
import subprocess

# List of suspicious keywords (you can expand this list)
suspicious_keywords = ['root', 'exploit', 'privilege', 'shell', 'inject']

# Track known PIDs to detect new processes
known_pids = set(p.pid for p in psutil.process_iter())

def is_suspicious(proc):
    try:
        name = proc.name().lower()
        cmdline = ' '.join(proc.cmdline()).lower()
        return any(keyword in name or keyword in cmdline for keyword in suspicious_keywords)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False

def trace_syscalls(pid):
    try:
        print(f"[+] Tracing syscalls for PID {pid}...")
        # Run strace for a short time and capture output
        result = subprocess.run(
            ["strace", "-p", str(pid), "-e", "trace=all", "-f", "-t", "-o", f"/tmp/syscalls_{pid}.log"],
            timeout=5,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print(f"[+] Syscall trace saved to /tmp/syscalls_{pid}.log")
    except subprocess.TimeoutExpired:
        print(f"[!] Tracing timeout for PID {pid}")
    except Exception as e:
        print(f"[!] Error tracing PID {pid}: {e}")

def monitor():
    print("[*] Monitoring for suspicious processes and syscall activity...")
    while True:
        current_pids = set(p.pid for p in psutil.process_iter())
        new_pids = current_pids - known_pids

        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                if is_suspicious(proc):
                    print(f"[!] Suspicious process detected: {proc.name()} (PID {pid})")
                    trace_syscalls(pid)

                    # Prompt user
                    user_input = input(f"[-] Terminate process {pid}? (yes/no): ").strip().lower()
                    if user_input == 'yes':
                        proc.terminate()
                        print(f"[+] Process {pid} terminated.")
                    else:
                        print(f"[-] Process {pid} left running.")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        known_pids.update(new_pids)
        time.sleep(2)

if __name__ == "__main__":
    try:
        monitor()
    except KeyboardInterrupt:
        print("\n[+] Monitoring stopped.")
