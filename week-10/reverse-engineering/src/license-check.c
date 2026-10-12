/*
 * license-check — a toy "offline licence validator".
 * ---------------------------------------------------------------------------
 * The program asks for a licence key and tells you whether it is valid. The
 * valid key is never written down in the binary in plaintext: it is stored
 * XOR-encrypted with a repeating key, and only reconstructed one byte at a
 * time inside the comparison loop. So running `strings` on the binary shows
 * you the prompts and the success banner, but NOT the key itself.
 *
 * That is the whole lesson of reverse engineering: "the secret is only on the
 * client" is never a defence. Every constant below — `enc`, `key`, the loop
 * that combines them — is right there in the machine code for anyone with
 * `objdump`, `gdb` or `radare2` to read. The encryption does not hide the key;
 * it only decides *which tool* recovers it.
 *
 * Nothing here is sensitive and nothing leaves the container. See README.md.
 */
#include <stdio.h>
#include <string.h>

/* The expected key, XOR-encrypted at rest with the repeating key below.
 * 18 bytes. These look like noise in `strings` output — that is the point. */
static const unsigned char enc[] = {
    0x11, 0x40, 0x42, 0x07, 0x42, 0x10, 0x40, 0x6b, 0x05,
    0x43, 0x3c, 0x12, 0x6b, 0x47, 0x5b, 0x52, 0x1f, 0x58
};

/* The repeating XOR key. Also plainly visible in the binary. */
static const unsigned char key[] = "cs440";

int main(void) {
    char input[64];

    printf("Enter licence key: ");
    fflush(stdout);
    if (!fgets(input, sizeof input, stdin))
        return 1;
    input[strcspn(input, "\n")] = '\0';   /* strip the trailing newline */

    const size_t n = sizeof enc;          /* expected length */
    if (strlen(input) != n) {
        puts("Denied.");
        return 1;
    }

    /* Compare byte-by-byte: input[i] XOR key == enc[i] for every i.
     * Equivalently, the valid key is enc[i] XOR key[i % 5]. */
    for (size_t i = 0; i < n; i++) {
        if ((unsigned char)(input[i] ^ key[i % (sizeof key - 1)]) != enc[i]) {
            puts("Denied.");
            return 1;
        }
    }

    /* Note there is NO flag string stored here: the key you just recovered
     * IS the flag. `strings` therefore cannot shortcut this challenge — you
     * have to reconstruct the key from `enc` and `key` to know what to type. */
    puts("Access granted.");
    printf("Submit this as your flag:  CS440{%s}\n", input);
    return 0;
}
