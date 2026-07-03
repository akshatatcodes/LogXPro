"""
response/network_block.py
-------------------------
Phase 5: Automated or analyst-triggered containment response.
Blocks malicious IP addresses using the native system firewall.
Supports Windows Firewall (via netsh) and Linux Firewalls (via iptables).
"""
import sys
import os
import subprocess

def block_ip(ip: str, approved_by: str = "analyst") -> bool:
    """
    Blocks incoming and outgoing connections to/from the target IP.
    Uses netsh on Windows and iptables on Linux.
    
    Args:
        ip: The target IP address to block.
        approved_by: User or automation rule that approved the block.
        
    Returns:
        True if the rules were successfully applied, False otherwise.
    """
    print(f"\n[RESPONSE ACTION] Triggered block action for malicious IP: {ip} (Approved by: {approved_by})")
    
    # 1. Windows platform
    if sys.platform.startswith("win"):
        cmd_out = f'netsh advfirewall firewall add rule name="LogXPro Block Outbound {ip}" dir=out action=block remoteip={ip}'
        cmd_in  = f'netsh advfirewall firewall add rule name="LogXPro Block Inbound {ip}" dir=in action=block remoteip={ip}'
        
        print(f"[ACTION REQUIRED] Run command in administrator PowerShell/cmd:\n  {cmd_out}\n  {cmd_in}")
        
        # Check administrative status on Windows
        import ctypes
        is_admin = False
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            pass
            
        if is_admin:
            try:
                subprocess.run(cmd_out, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.run(cmd_in, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                print(f"[+] Successfully blocked IP {ip} via Windows Defender Firewall.")
                return True
            except Exception as e:
                print(f"[!] Failed to execute Windows Firewall rules: {e}")
                return False
        else:
            print("[*] Running as non-admin. Skipping automatic Windows Firewall rule execution.")
            return False
            
    # 2. Linux platform
    else:
        cmd_out = f"sudo iptables -A OUTPUT -d {ip} -j DROP"
        cmd_in  = f"sudo iptables -A INPUT -s {ip} -j DROP"
        
        print(f"[ACTION REQUIRED] Run command in terminal:\n  {cmd_out}\n  {cmd_in}")
        
        try:
            # Check root on Linux
            if os.geteuid() == 0:
                subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                print(f"[+] Successfully blocked IP {ip} via iptables.")
                return True
            else:
                print("[*] Running as non-root. Skipping automatic iptables rule execution.")
                return False
        except AttributeError:
            pass
            
    return False
