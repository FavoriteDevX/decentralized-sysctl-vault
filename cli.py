import sys
import base64
from guardian_core import GuardianCryptosystem, ServiceOrchestrator

def execute_governance_pipeline():
    cryptosystem = GuardianCryptosystem()
    
    print("=" * 70)
    print("   ZERO-TRUST QUORUM-DRIVEN INFRASTRUCTURE ORCHESTRATOR SIMULATOR")
    print("=" * 70)
    
    # Configure environmental defaults based on architecture reference profiles
    target_service = "Print Spooler" if sys.platform == "win32" else "nginx"
    auth_token_payload = "ORCHESTRATION_STAGE_ALPHA_ACCESS_GRANTED"
    total_distributed_tokens = 5
    required_quorum_threshold = 3
    
    # Analyze current environment state prior to pipeline activation
    initial_status = ServiceOrchestrator.query_service_status(target_service)
    print(f"[*] Target Daemon Registry: '{target_service}' | Pre-evaluation State: [{initial_status}]")
    print(f"[*] Initializing Cryptographic Scheme Matrix: {required_quorum_threshold}-of-{total_distributed_tokens}")
    
    # Process original split operation
    encrypted_payload_package, keyspaces = cryptosystem.split_system_secret(
        auth_token_payload, required_quorum_threshold, total_distributed_tokens
    )
    print("[+] Core payload encrypted under AES-256-GCM. Secret keyspace split successfully.")
    
    print("\n" + "-" * 50)
    print(" PIPELINE EVENT 0x01: SUB-THRESHOLD INTERACTION (REJECT EXPECTED)")
    print("-" * 50)
    
    malformed_quorum = keyspaces[:2] # Provoking anomaly with only (Threshold - 1) tokens
    print(f"[!] Warning: Insufficient quorum presenting data nodes ({len(malformed_quorum)} presented).")
    
    try:
        cryptosystem.reconstruct_system_secret(encrypted_payload_package, malformed_quorum)
    except Exception:
        print("[+] Access Denied: Polynomial interpolation blocked. Cryptographic boundary secure.")
        print(f"[*] System Health: Target service '{target_service}' left completely isolated.")

    print("\n" + "-" * 50)
    print(" PIPELINE EVENT 0x02: VALID QUORUM CONVERGENCE (EXECUTION EXPECTED)")
    print("-" * 50)
    
    authorized_quorum = keyspaces[:3] # Satisfies the required Polynomial Quorum
    print(f"[+] Success: Required quorum established ({len(authorized_quorum)} signatures registered). Processing...")
    
    try:
        decrypted_auth_validation = cryptosystem.reconstruct_system_secret(encrypted_payload_package, authorized_quorum)
        
        if decrypted_auth_validation == auth_token_payload:
            print("[+] Authorization validated against state machine. Signature authenticity verified.")
            print("[*] Passing execution tokens down to OS orchestration interface layer...")
            
            # Execute physical runtime integration sequence
            runtime_success = ServiceOrchestrator.restart_target_service(target_service)
            
            if runtime_success:
                print("\n[==>] PIPELINE TASK COMPLETED: SYSTEM HARDWARE SERVICES SUCCESSFULY RECYCLED.")
            else:
                print("\n[==>] DEPLOYMENT ERROR: Auth pipeline cleared but operating system rejected runtime request.")
    except Exception as error_context:
        print(f"[-] Unhandled kernel-space execution fault: {error_context}")

if __name__ == "__main__":
    execute_governance_pipeline()
