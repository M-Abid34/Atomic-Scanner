import requests
import argparse

def banner(target, wordlist, threads):
    print(rf"""
=============================================
   D I R B O O S T  —  Directory Bruteforcer
=============================================
 Target   : {target}
 Wordlist : {wordlist}
 Threads  : {threads}
=============================================
""")
    
parser = argparse.ArgumentParser(description="Directory Brute Forcer")
parser.add_argument("url", help="The target URL")
parser.add_argument("wordlist", help="Path to the wordlist file")
parser.add_argument("-t", "--threads", type=int, default=4, help="Number of concurrent threads")
args = parser.parse_args()

def brute_force_directories(url, wordlist, threads):
    with open(wordlist, 'r') as file:
        directories = [line.strip() for line in file if line.strip()]
        for dir in directories:
            full_url = f"{url}/{dir}"
            response = requests.get(full_url)
            if response.status_code == 200:
                print(f"Found directory: {full_url}")
            else:
                continue

if __name__ == "__main__":
    if not args.url.startswith("http://") and not args.url.startswith("https://"):
        print("Please provide a valid URL starting with http:// or https://")
    else:
        banner(args.url, args.wordlist, args.threads)
        brute_force_directories(args.url, args.wordlist, args.threads)