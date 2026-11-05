"""Check packages through the full gateway logic: python cli_demo.py requests reqeusts"""
import logging
import sys

from gateway.evaluate import evaluate
from gateway.main import normalize


def print_result(package_name: str):
    print("\n" + "=" * 60)
    print(f"PACKGUARD RISK ANALYSIS: '{package_name}'")
    print("=" * 60)

    result = evaluate(normalize(package_name))
    signals = result.signals

    print(f"Risk Score : {result.score:.4f} / 1.0000")
    print(f"Decision   : {result.decision.upper()}")
    print(f"Baseline   : {signals.get('baseline_score', 'not available')}")
    print(f"AI model   : {signals.get('model_score', 'not available')}")
    print("\nReasons:")
    for idx, reason in enumerate(result.reasons, 1):
        print(f"  {idx}. {reason}")
    if signals.get("errors"):
        print(f"\nFailed checks: {signals['errors']}")
    print("=" * 60 + "\n")


def main():
    logging.disable(logging.WARNING)
    if len(sys.argv) > 1:
        for pkg in sys.argv[1:]:
            print_result(pkg)
        return

    print("Welcome to PackGuard!")
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
