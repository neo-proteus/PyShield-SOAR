from pyshield.decision.engine import Decision
from pyshield.response.generator import ResponseGenerator


def main():

    generator = ResponseGenerator(
        output_directory="output"
    )

    artifacts = generator.generate(
        indicator="203.0.113.50",
        decision=Decision.CONTAIN
    )

    print()
    print("=" * 50)
    print("       PYSHIELD-SOAR RESPONSE TEST")
    print("=" * 50)

    for artifact in artifacts:
        print(f"[+] Generated: {artifact}")

    print("=" * 50)


if __name__ == "__main__":
    main()