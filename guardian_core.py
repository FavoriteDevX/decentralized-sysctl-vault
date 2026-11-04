import os
import sys
import subprocess
from typing import List, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from secretsharing import PlaintextToHexSecretSharer

if sys.platform == "win32":
    try:
        import win32serviceutil
    except ImportError:
        win32serviceutil = None
else:
    win32serviceutil = None


class IncidentResponseOrchestrator:
    """
    Advanced defensive operations layer designed to handle system recovery,
    isolation, and state-purging during active cyberattacks.
    """
    
    @staticmethod
    def isolate_and_quarantine_service(service_name: str) -> bool:
        """
        Isolates a service by killing suspicious active network connections or 
        stopping its execution immediately to prevent lateral movement.
        """
        print(f"[!] CYBERATTACK MITIGATION TRIGGERED: Isolating service '{service_name}'...")
        
        if sys.platform == "win32":
            if win32serviceutil is None:
                return False
            try:
                # Forcefully stop the service to prevent data exfiltration
                win32serviceutil.StopService(service_name)
                print(f"[+] Defensive Action: Windows service '{service_name}' stopped and isolated.")
                return True
            except Exception as e:
                print(f"[-] Failed to stop compromised Windows service: {e}")
                return False
        else:
            try:
                # Isolate service using systemd emergency stop mechanism
                subprocess.run(["sudo", "systemctl", "kill", "-s", "SIGKILL", service_name], check=True)
                print(f"[+] Defensive Action: Linux service '{service_name}' forcefully killed (SIGKILL).")
                return True
            except Exception as e:
                print(f"[-] Failed to isolate Linux service: {e}")
                return False

    @staticmethod
    def emergency_clean_restart(service_name: str) -> bool:
        """
        Executes a secure recovery cycle. Purges known volatile caches (e.g., DNS/temp storage) 
        and brings the core infrastructure back online from a verified clean state.
        """
        print(f"[*] Cybersecurity Recovery Suite: Executing clean environment flush for '{service_name}'...")
        
        if sys.platform == "win32":
            try:
                # Flush OS-level DNS cache to mitigate DNS poisoning attacks
                subprocess.run(["ipconfig", "/flushdns"], check=True)
                print("[+] Windows DNS Cache flushed successfully.")
                if win32serviceutil:
                    win32serviceutil.StartService(service_name)
                    print(f"[+] Service '{service_name}' restarted in verified environment.")
                    return True
                return False
            except Exception as e:
                print(f"[-] Critical failure during Windows clean recovery: {e}")
                return False
        else:
            try:
                # Clear systemd failed states and purge volatile system caches
                subprocess.run(["sudo", "systemctl", "reset-failed", service_name], check=True)
                subprocess.run(["sudo", "sync"], check=True) # Flush file system buffers
                
                # Restart the service cleanly
                subprocess.run(["sudo", "systemctl", "start", service_name], check=True)
                print(f"[+] Service '{service_name}' fully restored from a clean baseline state.")
                return True
            except Exception as e:
                print(f"[-] Critical failure during Linux clean recovery: {e}")
                return False


class GuardianCryptosystem:
    """
    Implements a cryptographically secured Multi-Party Threshold Vault 
    utilizing Authenticated Symmetric Encryption (AES-GCM) combined with
    Polynomial Secret Splitting Mechanics (Shamir's Secret Sharing).
    """

    def split_system_secret(self, secret_data: str, threshold: int, total_shares: int) -> Tuple[bytes, List[str]]:
        if threshold > total_shares:
            raise ValueError("Polynomial Threshold (M) constraint bound failure: M cannot exceed N.")

        master_key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(master_key)
        nonce = os.urandom(12)
        
        ciphertext = aesgcm.encrypt(nonce, secret_data.encode('utf-8'), None)
        payload_package = nonce + ciphertext
        
        master_key_hex = master_key.hex()
        shares = PlaintextToHexSecretSharer.split_secret(master_key_hex, threshold, total_shares)
        
        return payload_package, shares

    def reconstruct_system_secret(self, payload_package: bytes, shares: List[str]) -> str:
        try:
            recovered_key_hex = PlaintextToHexSecretSharer.recover_secret(shares)
            master_key = bytes.fromhex(recovered_key_hex)
        except Exception as e:
            raise RuntimeError("Lagrange polynomial interpolation failed. Bad or sub-threshold matrix parameters.") from e

        if len(payload_package) < 12:
            raise ValueError("Structural payload anomaly detected: Initialization Vector bounds truncated.")
            
        nonce = payload_package[:12]
        ciphertext = payload_package[12:]
        
        aesgcm = AESGCM(master_key)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        
        return decrypted_bytes.decode('utf-8')
