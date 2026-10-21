# Week 10 — ret2libc challenge
# ---------------------------------------------------------------------------
# The same stack buffer overflow as the ret2win lab, but with no win() to jump
# to. You overflow a 64-byte buffer, overwrite the saved return address, and
# build a short ROP chain that returns into glibc's system("/bin/sh") to pop a
# shell — then read the flag yourself. Everything runs inside a throwaway
# container bound to nothing; the image is deleted on exit (`docker run --rm`).
#
#   docker build -t cs440-ret2libc .
#   docker run -it --rm cs440-ret2libc
#
# See README.md for the full walkthrough.
#
# Pinned to amd64 AND to a fixed Debian point release so the libc is identical
# on every host (Docker emulates amd64 on Apple Silicon / ARM). The exact libc
# matters here: the addresses of system() and "/bin/sh" come out of THIS libc,
# so pinning it keeps the README's example numbers reproducible.
FROM --platform=linux/amd64 debian:bookworm-slim

# The pwn toolkit, all inside the box:
#   gdb        -> run and inspect, read system()'s address and find "/bin/sh"
#   python3 / pwntools -> craft the ROP chain and send it the way real CTFs do
#                         (pwntools' ROP() also locates the `pop rdi; ret` gadget)
#   binutils   -> objdump, nm        file -> confirm the mitigations
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        gcc libc6-dev \
        gdb python3 python3-pip python3-dev \
        binutils file less procps \
 && pip3 install --no-cache-dir --break-system-packages pwntools \
 && rm -rf /var/lib/apt/lists/*

# Keep pwntools' terminal handling quiet (it warns if TERM is unset).
ENV TERM=xterm

# An unprivileged account to play from.
RUN useradd --create-home --shell /bin/bash player

# The flag, readable by anyone — the challenge is popping a shell, not bypassing
# file permissions. Once you have the shell, `cat /flag.txt` reads it.
RUN echo 'CS440{returned_into_libc_and_popped_a_shell}' > /flag.txt \
 && chmod 644 /flag.txt

# Build the vulnerable binary. Note the difference from ret2win: we switch OFF
# the canary and PIE, but we deliberately LEAVE NX (non-executable stack) ON —
# which is the default. That is the whole point of this lab:
#   -fno-stack-protector : no stack canary, so the overwrite is not detected
#   -no-pie              : fixed load address for the main binary
#   (no -z execstack)    : the stack stays NON-executable, so you CANNOT run
#                          shellcode off it — forcing you to reuse libc instead
# The source is left in /home/player/src so you can read it; reading it is how
# you would find this bug on a real target. Symbols are kept (-g) so system()
# and friends are easy to locate in libc from gdb.
COPY src/vuln.c /home/player/src/vuln.c
RUN gcc -g -O0 -fno-stack-protector -no-pie \
        -o /home/player/vuln /home/player/src/vuln.c \
 && chown -R root:player /home/player/src /home/player/vuln \
 && chmod 644 /home/player/src/vuln.c \
 && chmod 755 /home/player/vuln

USER player
WORKDIR /home/player
CMD ["/bin/bash"]
