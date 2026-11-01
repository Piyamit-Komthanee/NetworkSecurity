# Container 1: ReDoS (catastrophic regex backtracking) — a genuine CPU-exhaustion attack.
#
# We use an "evil" regex, the same mechanism the upstream CODAX repo used (r"^(a|a?)+b$"),
# instead of the paper's black==23.0.0 CVE: that black version does not exist on PyPI, and
# 23.1.0 (closest) did not reproduce a measurable ReDoS in testing. The evil regex below is a
# real ReDoS whose matching time grows exponentially with input length, so a single
# /vulnerable request burns one CPU for a tunable, long time while holding the connection.
#
#   /safe            -> trivial regex, returns in ~microseconds (benign baseline)
#   /vulnerable?n=NN -> evil regex on "a"*NN + "!"; time roughly doubles per +1 in NN.
#                       Measured in-container: n=22 ~1s, 24 ~4s, 26 ~25s, 28 ~120s.
import re
from flask import Flask, jsonify, request

app = Flask(__name__)

EVIL = re.compile(r"^(a|a?)+$")  # exponential backtracking when the string fails to match
SAFE = re.compile(r"^a+$")

DEFAULT_N = 24  # ~4s: clearly above any benign threshold, still bounded so it eventually closes


@app.route("/safe")
def safe():
    SAFE.search("a" * 50)  # always matches quickly
    return jsonify(message="ok")


@app.route("/vulnerable")
def vulnerable():
    n = int(request.args.get("n", str(DEFAULT_N)))
    EVIL.search("a" * n + "!")  # trailing '!' forces full backtracking
    return jsonify(message="done", n=n)


if __name__ == "__main__":
    # threaded=True: each connection gets its own thread, so an attack thread can spin on CPU
    # while benign requests are still served (matches the paper's per-request-thread model).
    app.run(host="0.0.0.0", port=8001, threaded=True)
