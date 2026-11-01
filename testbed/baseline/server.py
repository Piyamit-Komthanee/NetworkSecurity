# Container 3: clean control server (no vulnerability). All requests return fast.
# Also serves as the Algorithm 6 "heartbeat": a benign client hitting /safe here produces
# regular close() events that drive CODAX's periodic cross-container check even when the
# attacked containers never close their connections.
from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/safe")
@app.route("/")
def safe():
    return jsonify(message="ok")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8003, threaded=True)
