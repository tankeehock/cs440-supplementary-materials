/*
 * health-check — print a quick system health summary.
 * ---------------------------------------------------------------------------
 * Ships setuid-root so an operator can read privileged counters (load, disk)
 * without a password. That part is a legitimate reason for a SUID binary.
 *
 * The bug is two lines working together:
 *
 *   1. setuid(0)          — it drops to root up front "because some checks
 *                           need it", so the whole rest of the program, and
 *                           anything it spawns, runs as root.
 *   2. system("uptime")   — it names the helper commands WITHOUT an absolute
 *                           path, so the shell resolves them through $PATH,
 *                           and $PATH belongs to whoever launched the program.
 *
 * Either alone is survivable. Together they hand a root shell to any caller
 * who can put a file called `uptime` earlier in their $PATH. This is the most
 * common SUID mistake in the wild: escalate, then trust attacker-controlled
 * input (here, the environment).
 *
 * Modern Linux IGNORES the setuid bit on shell scripts, which is why a lab
 * like this needs a compiled binary — you cannot just chmod 4755 a .sh.
 */
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(void) {
    /* The mistake: become root before doing anything, and stay root. */
    setuid(0);
    setgid(0);

    puts("== system health ==");

    /* Bare command names -> resolved via $PATH -> caller controls them. */
    system("uptime");
    system("free -h");

    return 0;
}
