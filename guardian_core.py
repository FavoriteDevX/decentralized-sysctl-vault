import os
import sys
import subprocess
import json
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


class ProductionIncidentResponder:
    """
    Enterprise-grade incident response orchestrator capable of executing containment
    and environment sanitization protocols on live production environments.
    """
    
    @staticmethod
    def isolate_network_and_service(service_name: str) -> bool:
        """
        Executes immediate host-level containment. Stops the targeted service and 
        flushes routing or process hooks to break active malicious loops.
        """
        if sys.platform == "win32":
            if win32serviceutil is None:
                return False
            try:
                # Forcefully request the Service Control Manager to halt execution
                win32serviceutil.StopService(service_name)
                return True
            except Exception as e:
                sys.stderr.write(f"[ERROR] SCM manipulation failed for {service_name}: {e}\n")
                return False
        else:
            try:
                # Issue a SIGKILL signal directly via systemd to guarantee process termination
                subprocess.run(["sudo", "systemctl", "kill", "-s", "SIGKILL", service_name], check=True, capture_output=True)
                return True
            except subprocess.CalledProcessError as e:
                sys.stderr.write(f"[ERROR] systemctl intervention rejected: {e.stderr.decode()}\n")
                return False

    @staticmethod
    def execute_clean_bootstrap(service_name: str) -> bool:
        """
        Purges volatile system states, flushes local resolver caches to mitigate 
        cache poisoning, and restarts the service daemon into a verified state.
        """
        if sys.platform == "win32":
            try:
                # Flush the native OS DNS resolver cache to clear malicious routing redirection
                subprocess.run(["ipconfig", "/flushdns"], check=True, capture_output=True)
                if win32serviceutil:
                    win32serviceutil.StartService(service_name)
                    return True
                return False
            except Exception as e:
                sys.stderr.write(f"[ERROR] Windows environment flush failed: {e}\n")
                return False
        else:
            try:
                # Reset failed state flags in systemd, sync disks, and start a fresh worker process
                subprocess.run(["sudo", "systemctl", "reset-failed", service_name], check=True, capture_output=True)
                subprocess.run(["sudo", "sync"], check=True, capture_output=True)
                subprocess.run(["sudo", "systemctl", "start", service_name], check=True, capture_output=True)
                return True
            except subprocess.CalledProcessError as e:
                sys.stderr.write(f"[ERROR] Linux clean bootstrap failed: {e.stderr.decode()}\n")
                return False


class QuorumGatekeeper:
    """
    Cryptographic implementation of Shamir's Secret Sharing threshold scheme 
    coupled with authenticated AES-GCM encryption for multi-party infrastructure authorization.
    """

    def generate_emergency_vault(self, protection_token: str, threshold: int, total_shares: int) -> Tuple[bytes, List[str]]:
        """
        Encrypts the core management token and splinters the decryption key into independent cryptographic shares.
        """
        if threshold > total_shares:
            raise ValueError("Invalid threshold constraints: M cannot be greater than N.")

        master_encryption_key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(master_encryption_key)
        nonce = os.urandom(12)
        
        ciphertext = aesgcm.encrypt(nonce, protection_token.encode('utf-8'), None)
        encrypted_package = nonce + ciphertext
        
        shares = PlaintextToHexSecretSharer.split_secret(master_encryption_key.hex(), threshold, total_shares)
        return encrypted_package, shares

    def authorize_and_unlock(self, encrypted_package: bytes, presented_shares: List[str]) -> str:
        """
        Reconstructs the transient decryption key from the provided shares using polynomial interpolation.
        """
        try:
            recovered_key_hex = PlaintextToHexSecretSharer.recover_secret(presented_shares)
            master_encryption_key = bytes.fromhex(recovered_key_hex)
        except Exception as e:
            raise RuntimeError("Cryptographic quorum verification failed. Insufficient or invalid keys.") from e

        if len(encrypted_package) < 12:
            raise ValueError("Corrupted encrypted package package structure.")
            
        nonce = encrypted_package[:12]
        ciphertext = encrypted_package[12:]
        
        aesgcm = AESGCM(master_encryption_key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
