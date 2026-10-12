/*
 * stackview — watch your input overwrite the stack, one byte at a time.
 * ---------------------------------------------------------------------------
 * This is the program from the lecture slides, made runnable. Function X()
 * holds a tiny 10-byte buffer, prints the raw stack, copies your input into
 * the buffer with the unbounded strcpy(), then prints the raw stack AGAIN so
 * you can SEE what changed.
 *
 * The %p-with-no-arguments calls are the "trick to view the stack": printf is
 * told to print pointers but handed no values, so (in 32-bit cdecl) it reads
 * successive slots straight off the stack — buf, the saved frame pointer, and
 * the saved RETURN ADDRESS all show up in the dump. Watch the dump change as
 * your input gets longer and you will literally see the return address get
 * overwritten.
 *
 * The bug is one line: strcpy(buf, input) copies until it hits a NUL byte,
 * with no idea that buf is only 10 bytes. Anything longer runs off the end and
 * over whatever the compiler placed above buf on the stack.
 *
 * Built 32-bit, no canary, no PIE (see the Dockerfile) so the picture matches
 * the slides: 4-byte stack slots and fixed, readable code addresses. Nothing
 * here touches your host. See README.md.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* The prize. main() NEVER calls this — reaching it is the goal of Part 2.
 * Its address is what you will write over the saved return address. */
void secret(void) {
    puts("\n*** secret() reached: you overwrote the return address! ***");
    FILE *f = fopen("/flag.txt", "r");
    char flag[128];
    if (f && fgets(flag, sizeof flag, f))
        printf("Flag: %s", flag);
    if (f) fclose(f);
    fflush(stdout);
    exit(0);               /* leave cleanly instead of returning into rubble */
}

void X(const char *input) {
    char buf[10];

    /* Dump the stack BEFORE the copy. 14 slots = 56 bytes, enough to include
     * buf, the saved frame pointer and the saved return address. No arguments
     * are passed on purpose — that is the trick. */
    printf("My stack looks like:\n");
    printf("  [ 0] %p   [ 1] %p   [ 2] %p   [ 3] %p\n"
           "  [ 4] %p   [ 5] %p   [ 6] %p   [ 7] %p\n"
           "  [ 8] %p   [ 9] %p   [10] %p   [11] %p\n"
           "  [12] %p   [13] %p\n\n");

    /* THE BUG: unbounded copy into a 10-byte buffer. */
    strcpy(buf, input);
    printf("buf now holds: \"%s\"\n\n", buf);

    /* Dump the stack AFTER the copy — compare it slot-by-slot with the first
     * dump to see exactly which slots your input landed on. */
    printf("Now the stack looks like:\n");
    printf("  [ 0] %p   [ 1] %p   [ 2] %p   [ 3] %p\n"
           "  [ 4] %p   [ 5] %p   [ 6] %p   [ 7] %p\n"
           "  [ 8] %p   [ 9] %p   [10] %p   [11] %p\n"
           "  [12] %p   [13] %p\n\n");
}

int main(int argc, char **argv) {
    /* Unbuffered output so both stack dumps appear even when the program
     * crashes right after (an overwritten return address), and when you feed
     * it scripted input through a pipe instead of typing at a terminal. */
    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc < 2) {
        printf("usage: %s <input>\n", argv[0]);
        printf("try:   %s Hello\n", argv[0]);
        return 1;
    }

    X(argv[1]);

    /* If the return address is intact, control comes back here. If you
     * overwrote it with &secret, this line never prints. */
    puts("X() returned normally. (The return address was untouched.)");
    return 0;
}
