# Week 10 — stack-visualizer challenge
# ---------------------------------------------------------------------------
# The "watch your input overwrite the stack" program from the lecture slides,
# made runnable. You feed it longer and longer input, watch the %p stack dump
# change, find where the saved return address sits, and finally overwrite it
# with the address of secret() to capture the flag. Runs entirely inside a
# throwaway container bound to nothing; the image is deleted on exit.
#
#   docker build -t cs440-stackview .
#   docker run -it --rm cs440-stackview
#
# See README.md for the full walkthrough.
#
# Pinned to amd64 so the addresses/offsets match the walkthrough on every host
# (Docker emulates this on Apple Silicon / ARM). The challenge itself is a
# 32-bit binary — see the build step below for why.
FROM --platform=linux/amd64 debian:bookworm-slim

# gcc-multilib pulls the 32-bit toolchain and headers so we can build a 32-bit
# (-m32) binary. We build 32-bit on purpose: the slides' "%p with no arguments
# to view the stack" trick relies on 32-bit cdecl passing varargs on the stack
# (64-bit passes the first few in registers, which would hide the picture), and
# 32-bit gives the neat 4-byte stack slots and short code addresses you see on
# the slides.
RUN dpkg --add-architecture i386 \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        gcc gcc-multilib libc6-dev-i386 \
        gdb file python3 less procps \
 && rm -rf /var/lib/apt/lists/*

# An unprivileged account to play from.
RUN useradd --create-home --shell /bin/bash player

# The flag, readable by anyone — the challenge is reaching secret(), not
# bypassing file permissions.
RUN echo 'CS440{strcpy_wrote_right_over_the_return_address}' > /flag.txt \
 && chmod 644 /flag.txt

# Build the challenge with the defences off so the slide picture holds:
#   -m32                 : 32-bit, for the reasons above
#   -fno-stack-protector : no canary between buf and the saved return address
#   -no-pie -fno-pie     : fixed load address, so secret() is at a constant,
#                          readable address every run
# The source is left in /home/player/src so you can read it.
COPY src/stackview.c /home/player/src/stackview.c
RUN gcc -g -O0 -m32 -fno-stack-protector -no-pie -fno-pie \
        -o /home/player/stackview /home/player/src/stackview.c \
 && chown -R root:player /home/player/src /home/player/stackview \
 && chmod 644 /home/player/src/stackview.c \
 && chmod 755 /home/player/stackview

USER player
WORKDIR /home/player
CMD ["/bin/bash"]
