import hashlib
import sys
import time
import os

HASH_LENGTHS = {
    32: "md5",
    40: "sha1",
    56: "sha224",
    64: "sha256",
    96: "sha384",
    128: "sha512",
}

def detect_algorithm(target_hash):
    return HASH_LENGTHS.get(len(target_hash))

def crack_hashes(hash_file, wordlist):
    try:
        with open(hash_file, "r") as hf:
            hashes = [line.strip().lower() for line in hf if line.strip()]
    except FileNotFoundError:
        print("[-] Hash file not found.")
        return

    if not hashes:
        print("[-] No hashes loaded.")
        return

    # Group hashes by algorithm
    hash_groups = {}
    for h in hashes:
        algo = detect_algorithm(h)
        if not algo:
            print(f"[-] Could not detect algorithm for {h}")
            continue
        hash_groups.setdefault(algo, set()).add(h)

    if not hash_groups:
        print("[-] No valid hashes to process.")
        return

    print(f"[+] Loaded {len(hashes)} hash(es)")
    start_time = time.time()
    attempts = 0
    found = {}

    try:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as wl:
            for line in wl:
                word = line.strip()
                attempts += 1

                for algorithm, targets in hash_groups.items():
                    if not targets:
                        continue

                    h = hashlib.new(algorithm)
                    h.update(word.encode())
                    digest = h.hexdigest()

                    if digest in targets:
                        print(f"\n[+] Found match for {digest}: {word}")
                        found[digest] = word
                        targets.remove(digest)

                if attempts % 50000 == 0:
                    elapsed = time.time() - start_time
                    print(f"[*] Tried {attempts} words... ({elapsed:.1f}s)")

                # Stop early if all hashes cracked
                if all(len(v) == 0 for v in hash_groups.values()):
                    break

    except FileNotFoundError:
        print("[-] Wordlist file not found.")
        return

    elapsed = time.time() - start_time

    print("\n=== Results Summary ===")
    for h in hashes:
        if h in found:
            print(f"[+] {h} -> {found[h]}")
        else:
            print(f"[-] {h} -> Not found")

    print(f"\n[*] Total attempts: {attempts}")
    print(f"[*] Time elapsed: {elapsed:.2f}s")


def main():
    if len(sys.argv) != 3:
        print("Usage: python crax.py <hash_file> <wordlist>")
        sys.exit(1)

    hash_file = sys.argv[1]
    wordlist = sys.argv[2]

    crack_hashes(hash_file, wordlist)


if __name__ == "__main__":
    main()
