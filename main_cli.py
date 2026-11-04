import sys
import argparse
import base64
from guardian_core import QuorumGatekeeper, ProductionIncidentResponder

def main():
    parser = argparse.ArgumentParser(description="Zero-Trust Quorum-Based Emergency Infrastructure Recovery Tool")
    subparsers = parser.add_init = parser.add_subparsers(dest="command", required=True)

    # Command: Initialize Vault
    init_parser = subparsers.add_parser("initialize", help="Initialize a new secure cryptographic quorum vault")
    init_parser.add_argument("--token", required=True, help="The emergency verification phrase to encrypt")
    init_parser.add_argument("--threshold", type=int, required=True, help="Minimum number of keys needed to recover (M)")
    init_parser.add_argument("--shares", type=int, required=True, help="Total number of keys to distribute (N)")

    # Command: Recover Service
    recover_parser = subparsers.add_parser("recover", help="Authorize clean restart of a service using key quorum")
    recover_parser.add_argument("--service", required=True, help="Name of the system service (e.g., nginx, apache2, W3SVC)")
    recover_parser.add_argument("--vault", required=True, help="The Base64 encoded encrypted package generated during initialization")
    recover_parser.add_argument("--keys", nargs="+", required=True, help="Space-separated list of hex key shares provided by guardians")

    args = parser.parse_args()
    gatekeeper = QuorumGatekeeper()

    if args.command == "initialize":
        try:
            package, shares = gatekeeper.generate_emergency_vault(args.token, args.threshold, args.shares)
            print("[SUCCESS] Cryptographic Vault Initialized.")
            print(f"Vault Payload (Save this securely): {base64.b64encode(package).decode('utf-8')}\n")
            print("Distributed Guardian Keys:")
            for idx, share in enumerate(shares, 1):
                print(f"  Key #{idx}: {share}")
        except Exception as e:
            print(f"[FATAL] Initialization failed: {e}")

    elif args.command == "recover":
        print(f"[*] Incident Response Active: Isolation step triggered for safety on target '{args.service}'...")
        # Defensive isolation happens first to protect the server immediately
        ProductionIncidentResponder.isolate_network_and_service(args.service)
        print(f"[+] Isolation confirmed. Analyzing presented cryptographic credentials...")

        try:
            raw_package = base64.b64decode(args.vault)
            # Try to unlock the mechanism using the presented keys
            gatekeeper.authorize_and_unlock(raw_package, args.keys)
            print("[+] Authorization validated successfully. Quorum met.")
            
            # Action: Clean bootstrap execution
            if ProductionIncidentResponder.execute_clean_bootstrap(args.service):
                print(f"[SUCCESS] Service '{args.service}' recovered and brought online cleanly.")
            else:
                print(f"[FAILURE] Authorization succeeded, but system-level restart failed.")
        except Exception as e:
            print(f"[ACCESS DENIED] {e}")
            print(f"[!] Security Alert: Service '{args.service}' will remain isolated in quarantine.")

if __name__ == "__main__":
    main()
