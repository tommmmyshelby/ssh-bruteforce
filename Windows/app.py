from flask import Flask, render_template
import json

app = Flask(__name__)

@app.route("/")
def dashboard():

    try:
        with open("attack_data.json", "r") as f:
            attacks = json.load(f)

    except:
        attacks = []

    return render_template(
        "index.html",
        attacks=attacks
    )

if __name__ == "__main__":
    app.run(debug=True)