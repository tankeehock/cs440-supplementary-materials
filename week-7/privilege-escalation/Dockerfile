# Week 7 — privilege-escalation lab
# ---------------------------------------------------------------------------
# A deliberately misconfigured Linux host, in a container. You log in as the
# unprivileged user `student` and escalate to root three different ways, all
# from an interactive shell inside the box. Nothing here touches your machine:
# the image is thrown away when the container exits (`docker run --rm`).
#
#   docker build -t privesc-lab .
#   docker run -it --rm privesc-lab
#
# See README.md for the full walkthrough.
FROM debian:bookworm-slim

# Tools the student uses inside the box, plus a compiler to build the
# vulnerable binary at image-build time. gcc is left in so students can read
# and rebuild the source; a production image would never carry it.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        sudo gcc libc6-dev procps findutils \
 && rm -rf /var/lib/apt/lists/*

# ── The unprivileged account the student starts as ──────────────────────────
RUN useradd --create-home --shell /bin/bash student \
 && echo 'student:student' | chpasswd

# ── Vector A: a SUID-root binary that trusts $PATH (see src/health-check.c) ──
COPY src/health-check.c /tmp/health-check.c
RUN gcc -o /usr/local/bin/health-check /tmp/health-check.c \
 && chown root:root /usr/local/bin/health-check \
 && chmod 4755      /usr/local/bin/health-check \
 && rm /tmp/health-check.c

# ── Vector B: a sudo rule that grants a shell-capable binary, NOPASSWD ───────
# `find` can run arbitrary commands via -exec, so "just let them run find as
# root" is really "let them be root". This is a whole category on GTFOBins.
RUN echo 'student ALL=(root) NOPASSWD: /usr/bin/find' > /etc/sudoers.d/student \
 && chmod 440 /etc/sudoers.d/student

# ── Vector C: the sticky bit, shown by its presence and its absence ──────────
# /shared has the sticky bit (mode 1777): anyone may create files, but only a
# file's owner may delete it — so student cannot touch root's file.
RUN mkdir -p /shared \
 && chmod 1777 /shared \
 && echo 'owned by root, protected by the sticky bit' > /shared/root-note.txt \
 && chown root:root /shared/root-note.txt \
 && chmod 644       /shared/root-note.txt

# /incoming is world-writable but has NO sticky bit (mode 0777): the missing
# bit means student may delete or replace root's file, so any privileged
# process that later trusts /incoming/job.sh runs student's content instead.
RUN mkdir -p /incoming \
 && chmod 0777 /incoming \
 && echo '#!/bin/sh'                     >  /incoming/job.sh \
 && echo 'echo "nightly job, run by root"' >> /incoming/job.sh \
 && chown root:root /incoming/job.sh \
 && chmod 755       /incoming/job.sh

# ── The prize: proof of root, unreadable as student ──────────────────────────
RUN echo 'You are root. On a real host this file is /etc/shadow, the cron spool, or a pivot to the next box.' > /root/flag.txt \
 && chmod 600 /root/flag.txt

USER student
WORKDIR /home/student
CMD ["/bin/bash"]
