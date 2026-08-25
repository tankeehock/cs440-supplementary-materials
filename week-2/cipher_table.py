"""
Substitution vs Transposition — teaching demo with visible tables.

Now shows the actual transformation machinery:
  * Substitution: the full alphabet mapping table (plain -> cipher)
  * Transposition: the grid before (written row by row) and after
    (read column by column)

Run:  python ciphers_tables.py
"""

from collections import Counter
import string

ALPHABET = string.ascii_uppercase


# ---------------------------------------------------------------
# 1. SUBSTITUTION — Caesar cipher
# ---------------------------------------------------------------

def caesar_table(shift: int) -> dict[str, str]:
    """Build the substitution table: each plain letter -> cipher letter."""
    return {p: ALPHABET[(i + shift) % 26] for i, p in enumerate(ALPHABET)}


def show_substitution_table(shift: int) -> None:
    table = caesar_table(shift)
    print(f"  Substitution table (shift {shift}) — BEFORE -> AFTER:")
    print("    plain : " + ' '.join(ALPHABET))
    print("    cipher: " + ' '.join(table[p] for p in ALPHABET))
    print("            " + ' '.join('^' if p in 'ATE' else ' ' for p in ALPHABET)
          + "   (^ = letters used most below)")


def caesar_encrypt(plaintext: str, shift: int) -> str:
    table = caesar_table(shift)
    return ''.join(table.get(ch, ch) for ch in plaintext.upper())


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    inverse = {v: k for k, v in caesar_table(shift).items()}
    return ''.join(inverse.get(ch, ch) for ch in ciphertext.upper())


# ---------------------------------------------------------------
# 2. TRANSPOSITION — columnar transposition
# ---------------------------------------------------------------

def build_grid(text: str, num_cols: int) -> list[str]:
    """Write the text into rows of num_cols (pad the last row with X)."""
    text = text.replace(' ', '')
    text += 'X' * (-len(text) % num_cols)
    return [text[i:i + num_cols] for i in range(0, len(text), num_cols)]


def show_transposition_grid(text: str, num_cols: int) -> list[str]:
    """Print the BEFORE grid (row order) and AFTER reading (column order)."""
    grid = build_grid(text, num_cols)

    print(f"  BEFORE — plaintext written into the grid ROW by ROW:")
    print("           " + ' '.join(f"c{c+1}" for c in range(num_cols)))
    for r, row in enumerate(grid, 1):
        print(f"    row {r}:  " + '  '.join(row))

    print(f"\n  AFTER — ciphertext read off COLUMN by COLUMN:")
    columns = [''.join(row[c] for row in grid) for c in range(num_cols)]
    for c, col in enumerate(columns, 1):
        print(f"    col {c} (top to bottom): {col}")

    return columns


def columnar_encrypt(plaintext: str, num_cols: int) -> str:
    grid = build_grid(plaintext, num_cols)
    return ''.join(''.join(row[c] for row in grid) for c in range(num_cols))


def columnar_decrypt(ciphertext: str, num_cols: int) -> str:
    rows = len(ciphertext) // num_cols
    columns = [ciphertext[i * rows:(i + 1) * rows] for i in range(num_cols)]
    return ''.join(columns[c][r] for r in range(rows) for c in range(num_cols))


# ---------------------------------------------------------------
# 3. Frequency comparison — what each cipher leaks
# ---------------------------------------------------------------

def show_top_frequencies(label: str, text: str, n: int = 5) -> None:
    freqs = Counter(ch for ch in text.upper() if ch in ALPHABET)
    top = ', '.join(f"{ltr}:{cnt}" for ltr, cnt in freqs.most_common(n))
    print(f"  {label:<28} top letters -> {top}")


if __name__ == '__main__':
    message = "ATTACK THE EASTERN WALL AT DAWN AND HOLD THE GATE"
    caesar_key = 3
    columns_key = 5

    print("=" * 66)
    print("DEFINITIONS")
    print("=" * 66)
    print("""
  SUBSTITUTION
    Replaces each unit of plaintext (letter, bit, or block) with a
    different symbol according to a defined mapping, while leaving
    its position unchanged.
      -> changes WHAT the symbols are (positions preserved)
      -> provides CONFUSION (obscures key/ciphertext relationship)

  TRANSPOSITION
    Rearranges the positions of the plaintext units according to a
    defined rule, while leaving the symbols themselves unchanged.
      -> changes WHERE the symbols are (identities preserved)
      -> provides DIFFUSION (spreads structure across ciphertext)
      -> also called a 'permutation cipher' in classical texts

  Neither is secure alone: substitution preserves frequency
  patterns, transposition preserves the symbols. Modern ciphers
  (AES) interleave both across many rounds.
""")

    print("=" * 66)
    print("PLAINTEXT :", message)
    print("=" * 66)

    # --- Substitution demo ---
    print("\n[SUBSTITUTION - Caesar, shift 3]\n")
    show_substitution_table(caesar_key)
    sub_cipher = caesar_encrypt(message, caesar_key)
    print(f"\n  Plaintext : {message}")
    print(f"  Ciphertext: {sub_cipher}")
    print(f"  Decrypted : {caesar_decrypt(sub_cipher, caesar_key)}")
    print("\n  Every A became D, every T became W — positions untouched,")
    print("  identities replaced via the table above.")

    print("""
  UNDERSTANDING THE TABLE
  -----------------------
  The table is the ENTIRE cipher. Encryption is just a lookup:
  find the plaintext letter in the top row, output the letter
  below it. All the cryptography happened when the table was built.

  The table must be a BIJECTION: every cipher letter appears exactly
  once in the bottom row. If two plain letters mapped to the same
  cipher letter, decryption would be ambiguous.""")

    inverse = {v: k for k, v in caesar_table(caesar_key).items()}
    print("\n  Decryption uses the INVERTED table (rows swapped, re-sorted):")
    print("    cipher: " + ' '.join(ALPHABET))
    print("    plain : " + ' '.join(inverse[c] for c in ALPHABET))

    print("""
  THE TABLE IS THE KEY
  --------------------
  * Caesar allows only 26 tables (rotations) -> brute force in
    seconds. Worse: one known pair (A->D) reveals the WHOLE table.
  * A random table (any permutation) gives 26! = 4x10^26 tables
    (~88 bits) -> unbruteforceable, BUT still broken: the table is
    static, so every E encrypts identically and frequency analysis
    rebuilds the table entry by entry. Key size alone != security.
  * AES keeps the idea (its S-box is a 256-entry byte substitution
    table) but composes it: repeated rounds, mixed with permutation
    steps, varied by key material -> behaves like a random table
    over entire 128-bit blocks, too large for frequency analysis.""")

    # --- Transposition demo ---
    print("\n[TRANSPOSITION - Columnar, 5 columns]\n")
    columns = show_transposition_grid(message, columns_key)
    trans_cipher = columnar_encrypt(message, columns_key)
    print(f"\n  Ciphertext (cols joined): {trans_cipher}")
    print(f"  Decrypted               : {columnar_decrypt(trans_cipher, columns_key)}")
    print("\n  Every letter kept its identity — only its POSITION moved,")
    print("  according to the grid above.")

    print(f"""
  UNDERSTANDING THE GRID
  ----------------------
  The cipher is the MISMATCH between write and read direction:
  written row by row, read column by column. A letter at
  row r, column c moves to a completely different position in
  the output — but it is still the same letter.

  THE GRID SHAPE IS THE KEY
  -------------------------
  * Here the key is just the column count ({columns_key}). An attacker
    tries widths 2,3,4,5... rebuilds each grid, and reads the rows —
    when width {columns_key} is tried, English text appears. Seconds of work.
  * Keyed columnar variants read columns in a secret ORDER (given by
    a keyword), which enlarges the key space but still leaks: the
    ciphertext has perfectly normal English letter frequencies,
    which both fingerprints the method and enables anagram attacks.
  * AES keeps the idea too: its permutation steps (ShiftRows,
    MixColumns) are transpositions that relocate/spread bytes, so
    each round's substitution operates on freshly shuffled input.""")

    # --- What each one leaks ---
    print("\n[WHAT EACH CIPHER LEAKS - letter frequency comparison]")
    show_top_frequencies("Plaintext", message)
    show_top_frequencies("Substitution ciphertext", sub_cipher)
    show_top_frequencies("Transposition ciphertext", trans_cipher)

    print("""
Notice:
  * The substitution TABLE is the key — leak the table, lose everything.
    Frequencies shifted with the table (A:8 -> D:8), so analysis breaks it.
  * The transposition GRID SHAPE is the key — guess the column count,
    rebuild the grid. Frequencies are identical to the plaintext.
  * Modern ciphers (AES) interleave both: S-boxes are substitution
    tables, permutation layers are transpositions — repeated 10+ rounds.
""")