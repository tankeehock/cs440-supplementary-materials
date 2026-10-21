/*
 * vuln — the "ret2libc" buffer overflow, the sequel to ret2win.
 * ---------------------------------------------------------------------------
 * Same bug as the ret2win lab: read() accepts up to 256 bytes into a 64-byte
 * stack buffer, so your input runs off the end of the buffer and over the
 * SAVED RETURN ADDRESS. Overwrite that address and you choose where the CPU
 * goes when vuln() returns.
 *
 * But this time there is NO win() function to jump to. The binary contains no
 * code that prints the flag and no code that starts a shell — main() and
 * vuln() are all there is. So where do you send execution?
 *
 * The answer is the C library (libc). Every dynamically-linked program has all
 * of glibc mapped into its address space, and glibc contains system(), which
 * runs a shell command, and the literal bytes "/bin/sh" sitting in its .rodata.
 * You already have the code and the data you need — it just belongs to libc,
 * not to this program. "ret2libc" means: return into libc and reuse it.
 *
 * The stack frame of vuln(), low address to high (identical to ret2win):
 *
 *     [ buf: 64 bytes ][ saved RBP: 8 ][ saved return address: 8 ]
 *     ^you start writing here           ^you need to overwrite this
 *
 * So bytes 0..71 are padding and bytes 72..79 are the first thing the CPU will
 * "return" to. To call system("/bin/sh") on x86-64 you must also put the
 * address of "/bin/sh" into the RDI register (the first-argument register),
 * which a bare ret cannot do. So instead of one address you lay down a short
 * chain of them — a ROP chain — starting at offset 72:
 *
 *     [ 72 bytes padding ][ pop rdi ; ret ][ &"/bin/sh" ][ ret ][ &system ]
 *
 * Each address is an 8-byte "return" that runs a tiny snippet and returns into
 * the next. The `pop rdi ; ret` gadget loads &"/bin/sh" into RDI; the extra
 * bare `ret` is a 16-byte stack-alignment fix (see the README); then system
 * runs with RDI already pointing at "/bin/sh", and you get a shell.
 *
 * This works because the binary is built with the defences off (see the
 * Dockerfile): no stack canary catches the overwrite. Crucially, note what is
 * LEFT ON this time: NX (non-executable stack) is enabled, so you could not
 * just drop shellcode into buf and jump to it — the stack is not executable.
 * Being unable to run your own code is exactly why you reuse libc's. Nothing
 * here touches your host — see README.md.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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

    puts("== ret2libc ==");
    puts("There is no win() function this time. main() and vuln() are all there is.");
    puts("Everything you need to pop a shell is already in libc.");
    vuln();
    puts("vuln() returned normally. (If you are reading this, you missed.)");
    return 0;
}
