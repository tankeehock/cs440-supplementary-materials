/*
 * vuln — the "ret2win" buffer overflow, the first pwn challenge everyone meets.
 * ---------------------------------------------------------------------------
 * The program reads your name into a 64-byte stack buffer and greets you. It
 * never calls win(). win() reads the flag.
 *
 * The bug is one line: read() is told to accept up to 256 bytes into a buffer
 * that is only 64 bytes long. The extra bytes run off the end of the buffer,
 * straight over the other things the function stored next to it on the stack —
 * including the SAVED RETURN ADDRESS, the location the CPU jumps to when vuln()
 * finishes. Overwrite that with the address of win(), and when vuln() returns
 * the program "returns" into win() instead. You never called it; you redirected
 * the program counter into it.
 *
 * The stack frame of vuln(), from low address to high:
 *
 *     [ buf: 64 bytes ][ saved RBP: 8 ][ saved return address: 8 ]
 *     ^you start writing here           ^you need to overwrite this
 *
 * So the first 64 + 8 = 72 bytes are padding, and bytes 73..80 are the new
 * return address. Finding that "72" and that address is the whole exercise.
 *
 * This only works because the binary is built with the defences off (see the
 * Dockerfile): no stack canary would catch the overwrite, and no PIE/ASLR
 * means win() sits at a fixed, predictable address every run. Nothing here
 * touches your host — see README.md.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

/* The target. Never called in main() — you have to reach it yourself.
 *
 * It prints the flag with raw open/read/write rather than system() or printf
 * on purpose: those higher-level calls require the stack to be 16-byte aligned
 * (the x86-64 ABI), and a bare ret2win leaves it 8 bytes off, which would
 * crash inside libc with a `movaps` fault and distract from the real lesson.
 * The README's "A note on stack alignment" section explains that gotcha. */
void win(void) {
    const char *msg = "\n[+] Execution reached win(). The flag:\n";
    write(1, msg, 40);

    char flag[128];
    int fd = open("/flag.txt", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, flag, sizeof flag);
        if (n > 0) write(1, flag, (size_t)n);
        close(fd);
    }

    /* Exit cleanly with a raw syscall. Without this, win() would "return"
     * into the leftover padding on the stack and crash — the flag would still
     * print, but the segfault is a distracting way to end. _exit() is a thin
     * syscall wrapper, so it is not affected by the alignment gotcha above. */
    _exit(0);
}

void vuln(void) {
    char buf[64];
    puts("What is your name?");
    printf("> ");
    fflush(stdout);

    /* THE BUG: up to 256 bytes into a 64-byte buffer. */
    read(0, buf, 256);

    printf("Nice to meet you, %s\n", buf);
}

int main(void) {
    /* Unbuffered output so prompts appear in the right order when you pipe
     * a scripted payload into the program. */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    puts("== ret2win ==");
    puts("There is a win() function in here. main() never calls it.");
    vuln();
    puts("vuln() returned normally. (If you are reading this, you missed.)");
    return 0;
}
