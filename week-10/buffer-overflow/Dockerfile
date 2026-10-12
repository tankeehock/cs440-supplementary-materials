# Week 10 — buffer-overflow (ret2win) challenge
# ---------------------------------------------------------------------------
# A program with a classic stack buffer overflow. You overflow a 64-byte
# buffer to overwrite the saved return address and redirect execution into a
# win() function that prints the flag. Everything runs inside a throwaway
# container bound to nothing; the image is deleted on exit (`docker run --rm`).
#
#   docker build -t cs440-pwn .
#   docker run -it --rm cs440-pwn
#
# See README.md for the full walkthrough.
#
# Pinned to amd64 so the offsets and addresses in the README match on every
# host (Docker emulates this on Apple Silicon / ARM).
FROM --platform=linux/amd64 debian:bookworm-slim

# The pwn toolkit, all inside the box:
#   gdb        -> run and inspect, find win()'s address
#   python3 / pwntools -> craft and send the payload the way real CTFs do
#   binutils   -> objdump, nm        file -> confirm the mitigations are off
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

# The flag, readable by anyone — the challenge is reaching the code that
# prints it, not bypassing file permissions.
RUN echo 'CS440{you_control_the_program_counter_now}' > /flag.txt \
 && chmod 644 /flag.txt

# Build the vulnerable binary with the three mitigations that would otherwise
# make this lab impossible switched OFF, on purpose:
#   -fno-stack-protector : no stack canary, so the overwrite is not detected
#   -no-pie              : fixed load address, so win() is at a constant place
#   -z noexecstack is the default and is FINE here — ret2win needs no shellcode,
#                          it only reuses code already in the binary.
# The source is left in /home/player/src so you can read it; reading it is
# encouraged — real reverse engineering is how you would find this bug without
# the source. The binary keeps symbols (-g) to make win() easy to locate in a
# first lab.
COPY src/vuln.c /home/player/src/vuln.c
RUN gcc -g -O0 -fno-stack-protector -no-pie \
        -o /home/player/vuln /home/player/src/vuln.c \
 && chown -R root:player /home/player/src /home/player/vuln \
 && chmod 644 /home/player/src/vuln.c \
 && chmod 755 /home/player/vuln

USER player
WORKDIR /home/player
CMD ["/bin/bash"]
