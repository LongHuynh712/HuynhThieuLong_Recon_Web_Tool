# =========================
# FILE: app.py
# =========================

from flask import Flask, render_template, request
from scanner import scan_target

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    report = ""

    if request.method == "POST":
        url = request.form.get("url")

        if url:
            if not url.startswith("http"):
                url = "https://" + url

            report = scan_target(url)

    return render_template("index.html", report=report)

if __name__ == "__main__":
    app.run(debug=True)