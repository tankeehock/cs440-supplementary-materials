# Week 10 — reverse-engineering challenge
# ---------------------------------------------------------------------------
# A compiled "licence validator" whose valid key is XOR-encrypted in the
# binary. You never get the source inside the box — you recover the key by
# READING the compiled program with the standard RE toolkit, then feed the key
# back in to print the flag. Nothing here listens on a network; the image is
# thrown away when the container exits (`docker run --rm`).
#
#   docker build -t cs440-rev .
#   docker run -it --rm cs440-rev
#
# See README.md for the full walkthrough.
#
# Pinned to amd64 so the disassembly in the README matches on every host
# (Docker emulates this on Apple Silicon / ARM).
FROM --platform=linux/amd64 debian:bookworm-slim

# The reverse-engineer's starter kit, all inside the box:
#   binutils  -> objdump, nm, strings      file -> identify the binary
#   gdb       -> run and inspect it live
#   python3   -> do the XOR by hand
# gcc is only used at build time to compile the challenge; see below.
# (Prefer a GUI decompiler? Ghidra on your HOST reads the same binary — copy it
# out with `docker cp` — but everything in this lab is doable with objdump/gdb.)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        gcc libc6-dev \
        binutils file gdb python3 \
        less vim-tiny procps \
 && rm -rf /var/lib/apt/lists/*

# An unprivileged account to work from — the challenge needs no privilege.
RUN useradd --create-home --shell /bin/bash player

# Build the challenge binary, then DELETE the source so the only way to the
# answer is through the compiled program. Built with symbols (-g) and without
# optimisation (-O0) to keep the disassembly readable for a first lab; a real
# target would be stripped and optimised, which is simply the next difficulty.
COPY src/license-check.c /tmp/license-check.c
RUN gcc -g -O0 -o /home/player/license-check /tmp/license-check.c \
 && chown root:root /home/player/license-check \
 && chmod 755       /home/player/license-check \
 && rm /tmp/license-check.c

USER player
WORKDIR /home/player
CMD ["/bin/bash"]
