import sys
from guardian_core import GuardianCryptosystem, IncidentResponseOrchestrator

def run_cyber_incident_pipeline():
    cryptosystem = GuardianCryptosystem()
    
    print("=" * 75)
    print("   ZERO-TRUST SECURE RECOVERY & CYBER INCIDENT RESPONSE PIPELINE")
    print("=" * 75)
    
    target_service = "Print Spooler" if sys.platform == "win32" else "nginx"
    incident_auth_token = "CYBER_DEFENSE_EMERGENCY_RECOVERY_PROTOCOL_ACTIVE"
    total_guardians = 5
    required_quorum = 3
    
    # 1. Distribute keys to guardians before any attack occurs
    encrypted_package, guardian_keys = cryptosystem.split_system_secret(
        incident_auth_token, required_quorum, total_guardians
    )
    print("[+] Emergency Incident Response Keys distributed safely to Guardians.")
    
    print("\n" + "!" * 75)
    print(" ALERT: CATASTROPHIC CYBERATTACK DETECTED (RANSOMWARE / DESTRUCTION ATTEMPT)")
    print("!" * 75)
    print(f"[*] Corrupted data stream detected targeting service: '{target_service}'")
    
    # 2. Automated Initial Defense: Quarantine immediately to protect other network components
    # (This action does not require quorum because it is a defensive lockdown)
    IncidentResponseOrchestrator.isolate_and_quarantine_service(target_service)
    print(f"[!] System Status: Service '{target_service}' locked in quarantine zone.")
    
    print("\n" + "-" * 50)
    print(" EMERGENCY RECOVERY PHASE: COLLECTING GUARDIAN QUORUM")
    print("-" * 50)
    
    # Simulating 3 authorized guardians joining forces during the panic to recover the infrastructure
    active_quorum = guardian_keys[:3]
    print(f"[*] {len(active_quorum)} Global Guardians verified. Authenticating recovery sequence...")
    
    try:
        decrypted_token = cryptosystem.reconstruct_system_secret(encrypted_package, active_quorum)
        
        if decrypted_token == incident_auth_token:
            print("[SUCCESS] Cryptographic consensus established. Recovery signature verified.")
            print("[*] Launching system purge and emergency clean bootstrap...")
            
            # 3. Secure Clean Restart: Clear infected registers/caches and spin up safely
            recovery_success = IncidentResponseOrchestrator.emergency_clean_restart(target_service)
            
            if recovery_success:
                print("\n[==>] INCIDENT RESOLVED: INFRASTRUCTURE RESTORED SAFELY VIA CRYPTOGRAPHIC QUORUM.")
            else:
                print("\n[==>] CRITICAL EXCEPTION: Cryptographic verification passed, but system level injection failed.")
    except Exception as e:
        print(f"[-] Forensic Fault: Cryptographic recovery blocked due to compromised parameter data: {e}")

if __name__ == "__main__":
    run_cyber_incident_pipeline()
