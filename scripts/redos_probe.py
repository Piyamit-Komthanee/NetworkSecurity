# Calibrate a genuine catastrophic-backtracking ReDoS (evil regex) in the redos container.
# This is the real ReDoS mechanism the upstream CODAX repo used (r"^(a|a?)+b$").
# Run inside the redos container:  docker exec -i codax_redos python < scripts/redos_probe.py
import re, time

evil = re.compile(r"^(a|a?)+$")  # exponential backtracking on a non-matching tail


def t(n):
    s = "a" * n + "!"  # trailing '!' never matches -> forces full backtracking
    a = time.perf_counter()
    evil.search(s)
    return round(time.perf_counter() - a, 4)


for n in range(18, 34, 2):
    print(f"n={n:3d}  {t(n):9} s")
