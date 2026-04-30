from checker import analyze

def print_result(result):
    icons = {"SAFE": "✅", "SUSPICIOUS": "⚠️ ", "PHISHING": "🚨"}
    colors = {"SAFE": "\033[92m", "SUSPICIOUS": "\033[93m", "PHISHING": "\033[91m"}
    reset = "\033[0m"

    icon    = icons[result["verdict"]]
    color   = colors[result["verdict"]]
    verdict = result["verdict"]
    score   = result["score"]

    print(f"\n{'='*60}")
    print(f"URL     : {result['url']}")
    print(f"Result  : {color}{icon} {verdict} — {score} flag(s){reset}")
    print(f"{'─'*60}")

    if result["flags"]:
        print("  Red flags found:")
        for name, msg in result["flags"]:
            print(f"    ✗ [{name}] {msg}")

    if result["passes"]:
        print("  Checks passed:")
        for name, msg in result["passes"]:
            print(f"    ✓ [{name}] {msg}")

    print(f"{'='*60}")


def main():
    # Test URLs
    test_urls = [
        "https://google.com",
        "https://facebook.com",
        "http://paypal-verify.tk/login?suspended=true",
        "http://192.168.1.1/bank/login",
        "https://secure-amazon-login.verify-account.xyz/update",
        "https://apple.com.phishing-site.ml/id/verify",
    ]

    print("\n PHISHING URL DETECTOR")
    print(" Scanning all URLs...\n")

    for url in test_urls:
        result = analyze(url)
        print_result(result)


if __name__ == "__main__":
    main()