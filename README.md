# Crax
Crax is a lightweight, wordlist-based hash auditing tool written in Python and developed on Android using Termux.

It automatically detects common hash algorithms based on hash length and performs memory-efficient, line-by-line wordlist processing. The tool is designed to run reliably on low-resource systems without loading entire wordlists into memory. Supported algorithms: MD5, SHA1, SHA224, SHA256, SHA384, and SHA512.

Usage: `python crax.py <hash> <wordlist> [algorithm]`, if no algorithm is specified, Crax will attempt to detect it automatically.
