import csv
from checker import analyze

INPUT_FILE  = "urls.txt"
OUTPUT_FILE = "report.csv"


def scan_all():
    # Read URLs from file
    with open(INPUT_FILE, "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    results = []
    for url in urls:
        r = analyze(url)
        results.append({
            "url":       r["url"],
            "verdict":   r["verdict"],
            "flags":     r["score"],
            "details":   " | ".join(msg for _, msg in r["flags"]) or "None"
        })

    # Write to CSV
    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "verdict", "flags", "details"])
        writer.writeheader()
        writer.writerows(results)

    # Print summary
    total     = len(results)
    safe      = sum(1 for r in results if r["verdict"] == "SAFE")
    suspicious = sum(1 for r in results if r["verdict"] == "SUSPICIOUS")
    phishing  = sum(1 for r in results if r["verdict"] == "PHISHING")

    print(f"\nScan complete — {total} URLs checked")
    print(f"  Safe       : {safe}")
    print(f"  Suspicious : {suspicious}")
    print(f"  Phishing   : {phishing}")
    print(f"\nReport saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    scan_all()