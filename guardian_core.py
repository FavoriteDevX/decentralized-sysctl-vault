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


class ServiceOrchestrator:
    """
    Provides cross-platform systems management layer interfacing with native OS 
    Service Control Managers (Windows Services API and Linux systemd sub-systems).
    """
    
    @staticmethod
    def query_service_status(service_name: str) -> str:
        """
        Interrogates the host operating system to determine the runtime status of a service.
        """
        if sys.platform == "win32":
            if win32serviceutil is None:
                return "UNKNOWN (pywin32 missing)"
            try:
                # Query service status index 1 represents current execution state
                # State 4 corresponds to SERVICE_RUNNING
                status_code = win32serviceutil.QueryServiceStatus(service_name)[1]
                return "RUNNING" if status_code == 4 else "STOPPED/INACTIVE"
            except Exception:
                return "SERVICE_NOT_FOUND"
        else:
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", service_name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                return "RUNNING" if result.stdout.strip() == "active" else "STOPPED/INACTIVE"
            except Exception:
                return "SERVICE_NOT_FOUND"

    @staticmethod
    def restart_target_service(service_name: str) -> bool:
        """
        Dispatches native process-level execution calls to cycle target service states.
        """
        print(f"[*] Initializing lifecycle state modification for: '{service_name}'")
        
        # 1. Native Windows Service Control Manager Implementation
        if sys.platform == "win32":
            if win32serviceutil is None:
                print("[-] Fatal: Win32 execution libraries unavailable on host context.")
                return False
            try:
                win32serviceutil.RestartService(service_name)
                print(f"[+] Native Windows pipe signals transmitted. '{service_name}' cycled.")
                return True
            except Exception as e:
                print(f"[-] Windows Service Control Manager exception encountered: {e}")
                return False
                
        # 2. Native POSIX Linux systemd Implementation
        elif sys.platform.startswith("linux") or sys.platform == "darwin":
            try:
                subprocess.run(
                    ["sudo", "systemctl", "restart", service_name],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                print(f"[+] POSIX signal accepted. Linux systemd service '{service_name}' recycled.")
                return True
            except subprocess.CalledProcessError as e:
                print(f"[-] systemctl binary rejected parameter constraints: {e.stderr.decode('utf-8').strip()}")
                return False
            except Exception as e:
                print(f"[-] Low-level POSIX kernel/sub-process execution error: {e}")
                return False
        else:
            print(f"[-] Execution environment platform unmapped: {sys.platform}")
            return False


class GuardianCryptosystem:
    """
    Implements a cryptographically secured Multi-Party Threshold Vault 
    utilizing Authenticated Symmetric Encryption (AES-GCM) combined with
    Polynomial Secret Splitting Mechanics (Shamir's Secret Sharing).
    """

    def split_system_secret(self, secret_data: str, threshold: int, total_shares: int) -> Tuple[bytes, List[str]]:
        """
        Encrypts an arbitrary system execution payload token and splits the key into Shamir shards.
        """
        if threshold > total_shares:
            raise ValueError("Polynomial Threshold (M) constraint bound failure: M cannot exceed N.")

        # Generate cryptographic 256-bit entropy array
        master_key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(master_key)
        nonce = os.urandom(12) # Standard 96-bit initialization vector
        
        ciphertext = aesgcm.encrypt(nonce, secret_data.encode('utf-8'), None)
        payload_package = nonce + ciphertext
        
        # Polynomial distribution across split vectors
        master_key_hex = master_key.hex()
        shares = PlaintextToHexSecretSharer.split_secret(master_key_hex, threshold, total_shares)
        
        return payload_package, shares

    def reconstruct_system_secret(self, payload_package: bytes, shares: List[str]) -> str:
        """
        Evaluates mathematical shares to recompile the transient key matrix and decrypt the system payload.
        """
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
