import sys
import json
from packguard.risk.service import score_package

def print_result(package_name: str):
    print("\n" + "=" * 60)
    print(f"PACKGUARD AI RISK ANALYSIS: '{package_name}'")
    print("=" * 60)
    
    result = score_package(package_name)
    
    score = result["score"]
    decision = result["decision"].upper()
    
    # Visual status
    if decision == "ALLOW":
        badge = "[ SAFE / ALLOWED ]"
    elif decision == "WARN":
        badge = "[ WARNING / SUSPICIOUS ]"
    else:
        badge = "[ BLOCKED / HIGH RISK ]"
        
    print(f"Risk Score : {score:.4f} / 1.0000")
    print(f"Decision   : {badge}")
    print("\nTop Contributing Reasons (SHAP XAI):")
    for idx, reason in enumerate(result["reasons"], 1):
        print(f"  {idx}. {reason}")
        
    print("\nUnderlying Security Signals:")
    for k, v in result["signals"].items():
        print(f"  - {k:<25}: {v}")
    print("=" * 60 + "\n")

def main():
    if len(sys.argv) > 1:
        # Argument passed via command line
        for pkg in sys.argv[1:]:
            print_result(pkg)
    else:
        # Interactive loop
        print("Welcome to PackGuard AI Risk Checker!")
        print("Type any Python package name to evaluate (or 'exit' to quit):\n")
        while True:
            try:
                pkg = input("Enter package name > ").strip()
                if not pkg or pkg.lower() in ("exit", "quit", "q"):
                    break
                print_result(pkg)
            except (KeyboardInterrupt, EOFError):
                break

if __name__ == "__main__":
    main()
