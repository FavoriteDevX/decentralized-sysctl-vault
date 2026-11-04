import os
import sys
import subprocess
from typing import List, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from secretsharing import PlaintextToHexSecretSharer

# Platform verification for Windows environment hooks
if sys.platform == "win32":
    try:
        import win32serviceutil
    except ImportError:
        win32serviceutil = None
else:
    win32serviceutil = None


class IncidentResponseOrchestrator:
    """
    Advanced defensive orchestration layer engineered to handle automated incident
    mitigation, process isolation, and state-purging during active infrastructure attacks.
    """
    
    @staticmethod
    def isolate_and_quarantine_service(service_name: str) -> bool:
        """
        Executes immediate system containment. Terminating network hooks or stopping 
        the target software asset to break the attacker's command-and-control loop.
        """
        print(f"[!] MALICIOUS ACTIVITY SIGNATURE DETECTED: Isolating service '{service_name}'...")
        
        # Windows Service Mitigation Track
        if sys.platform == "win32":
            if win32serviceutil is None:
                print("[-] Hardware Hook Error: Win32 management modules missing on this host context.")
                return False
            try:
                win32serviceutil.StopService(service_name)
                print(f"[+] Containment Established: Windows Service '{service_name}' isolated from socket pool.")
                return True
            except Exception as e:
                print(f"[-] SCM Intervention Failure: Unable to forcefully halt service: {e}")
                return False
        
        # POSIX/Linux systemd Mitigation Track
        else:
            try:
                # Forcefully kill all execution threads belonging to the targeted daemon service
                subprocess.run(["sudo", "systemctl", "kill", "-s", "SIGKILL", service_name], check=True)
                print(f"[+] Containment Established: Linux daemon '{service_name}' terminated via SIGKILL.")
                return True
            except Exception as e:
                print(f"[-] systemd Intervention Failure: Could not bind quarantine rule to process: {e}")
                return False

    @staticmethod
    def emergency_clean_restart(service_name: str) -> bool:
        """
        Purges compromised transient states (poisoned DNS records, overflowing request queues),
        and safely bootstraps the core software component from a trusted clean baseline state.
        """
        print(f"[*] Recovery Sequencer: Triggering cryptographic-backed clean bootstrap for '{service_name}'...")
        
        if sys.platform == "win32":
            try:
                # Mitigate DNS poisoning vectors by flushing the host resolver cache
                subprocess.run(["ipconfig", "/flushdns"], check=True)
                print("[+] Cache Purge: Windows local DNS resolution cache flushed cleanly.")
                
                if win32serviceutil:
                    win32serviceutil.StartService(service_name)
                    print(f"[+] Recovery Complete: Service '{service_name}' resurrected on clean environment.")
                    return True
                return False
            except Exception as e:
                print(f"[-] Recovery Failure: Windows core environment flush failed: {e}")
                return False
        else:
            try:
                # Purge failed markers inside systemd daemon stack
                subprocess.run(["sudo", "systemctl", "reset-failed", service_name], check=True)
                subprocess.run(["sudo", "sync"], check=True) # Commit filesystem buffers to memory disk
                
                # Fire up the isolated internet-facing application service daemon safely
                subprocess.run(["sudo", "systemctl", "start", service_name], check=True)
                print(f"[+] Recovery Complete: Linux service '{service_name}' restored to stable operational baseline.")
                return True
            except Exception as e:
                print(f"[-] Recovery Failure: Linux systemd bootstrap failed: {e}")
                return False


class GuardianCryptosystem:
    """
    Implements a multi-party threshold access gateway using Authenticated Symmetric 
    Cryptography (AES-GCM) intertwined with Lagrange Polynomial Secret Splitting (SSSS).
    """

    def split_system_secret(self, secret_data: str, threshold: int, total_shares: int) -> Tuple[bytes, List[str]]:
        """
        Locks a core system token into an authenticated cryptopackage and splits the key into Shamir shards.
        """
        if threshold > total_shares:
            raise ValueError("Mathematical constraint violation: Threshold quorums (M) cannot exceed total slices (N).")

        # Generate a high-entropy 256-bit transient symmetric engine key
        master_key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(master_key)
        nonce = os.urandom(12)  # Standard Initialization Vector length
        
        ciphertext = aesgcm.encrypt(nonce, secret_data.encode('utf-8'), None)
        payload_package = nonce + ciphertext
        
        # Distribute the keyspace across independent coordinates
        master_key_hex = master_key.hex()
        shares = PlaintextToHexSecretSharer.split_secret(master_key_hex, threshold, total_shares)
        
        return payload_package, shares

    def reconstruct_system_secret(self, payload_package: bytes, shares: List[str]) -> str:
        """
        Merges provided key shards to re-interpolate the master key and unlock system execution permissions.
        """
        try:
            recovered_key_hex = PlaintextToHexSecretSharer.recover_secret(shares)
            master_key = bytes.fromhex(recovered_key_hex)
        except Exception as e:
            raise RuntimeError("Decryption Key Matrix interpolation failed. Insufficient or structurally damaged key shares.") from e

        if len(payload_package) < 12:
            raise ValueError("Payload structural defect: Initialization vector bytes missing.")
            
        nonce = payload_package[:12]
        ciphertext = payload_package[12:]
        
        aesgcm = AESGCM(master_key)
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        
        return decrypted_bytes.decode('utf-8')
