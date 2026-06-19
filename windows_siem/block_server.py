from flask import Flask, request, jsonify
import os

app = Flask(__name__)


# ----------------------------
# BLOCK ENDPOINT
# ----------------------------
@app.route("/block", methods=["POST"])
def block():

    data = request.get_json()
    ip = data.get("ip")

    print(f"[BLOCK SERVER HIT] IP: {ip}")

    if not ip:
        return jsonify({"error": "no ip provided"}), 400

    try:
        # ----------------------------
        # STEP 1: UFW BLOCK (VISIBLE RULE)
        # ----------------------------
        os.system(f"sudo ufw insert 1 deny from {ip} to any port 22 proto tcp")

        # ----------------------------
        # STEP 2: KILL ACTIVE CONNECTIONS
        # ----------------------------
        os.system(f"sudo conntrack -D -s {ip}")

        # ----------------------------
        # STEP 3: FORCE CLOSE SSH SESSIONS
        # ----------------------------
        os.system(f"sudo ss -K src {ip}")

        # ----------------------------
        # STEP 4: RAW DROP (EXTRA SAFETY)
        # ----------------------------
        os.system(f"sudo iptables -I INPUT -s {ip} -j DROP")

        print(f"[BLOCK SUCCESS] IP fully blocked → {ip}")

        return jsonify({
            "status": "blocked",
            "ip": ip
        })

    except Exception as e:
        print(f"[BLOCK ERROR] {e}")
        return jsonify({
            "status": "failed",
            "error": str(e)
        }), 500


# ----------------------------
# RUN SERVER
# ----------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)