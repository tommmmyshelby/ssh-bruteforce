from flask import (
    Flask,
    request,
    jsonify,
    render_template
)

from database import (
    initialize_database,
    insert_event,
    get_dashboard_data
)

from detector_service import calculate_risk

app = Flask(__name__)

initialize_database()


@app.route("/logs", methods=["POST"])
def receive_logs():

    data = request.json

    events = data.get("events", [])

    inserted = 0

    for event in events:

        insert_event(
            event["ip"],
            event["username"],
            event["event_type"],
            event["timestamp"]
        )

        inserted += 1

    print(
        f"Received and stored "
        f"{inserted} SSH event(s)"
    )

    calculate_risk()

    print("Detector executed.")

    return jsonify({
        "status": "success",
        "stored": inserted
    }), 200


@app.route("/")
def dashboard():

    data = get_dashboard_data()

    return render_template(
        "dashboard.html",
        data=data
    )


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )