from flask import Flask

app = Flask(__name__)


@app.route("/admin/reports")
@admin_required
def admin_reports():
    return list_reports()


@app.route("/login", methods=["POST"])
@rate_limit("5/minute")
def login():
    return do_login()
