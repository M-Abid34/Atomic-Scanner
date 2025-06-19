import requests
import base64

def fetch_payloads(raw_url, output_file):
    try:
        print(f"[+] Downloading payloads from: {raw_url}")
        response = requests.get(raw_url, timeout=10)
        response.raise_for_status()

        lines = response.text.splitlines()
        payloads = [line.strip() for line in lines if line.strip() and not line.startswith("#")]

        with open(output_file, "w", encoding="utf-8") as f:
            for payload in payloads:
                f.write(payload + "\n")

        print(f"[+] Saved {len(payloads)} original payloads to: {output_file}")
    except Exception as e:
        print(f"[-] Error downloading payloads: {e}")

def bypass_filters(payload):
    """
    Returns a single bypassed version of the payload.
    You can modify this to apply multiple techniques.
    """
    # Example: combine HTML encoding and script breaking
    if "<" in payload or "script" in payload:
        payload = payload.replace("<", "&lt;").replace(">", "&gt;")
        payload = payload.replace("script", "scr<script></script>ipt")

    # Add base64 variant
    return base64.b64encode(payload.encode()).decode()

def process_payloads(input_file, output_file):
    bypassed_lines = []

    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            original = line.strip()
            if not original:
                continue
            bypassed = bypass_filters(original)
            bypassed_lines.append(f"{original}__{bypassed}")

    with open(output_file, "w", encoding="utf-8") as f:
        for line in bypassed_lines:
            f.write(line + "\n")

    print(f"[+] Written {len(bypassed_lines)} bypassed payloads to: {output_file}")

# === MAIN FLOW ===
if __name__ == "__main__":
    # Step 1: Download payloads
    xss_raw_url = "https://raw.githubusercontent.com/payloadbox/xss-payload-list/master/README.md"
    original_file = "xss_raw_payloads.txt"
    output_file = "xss_bypassed_payloads.txt"

    fetch_payloads(xss_raw_url, original_file)
    process_payloads(original_file, output_file)
