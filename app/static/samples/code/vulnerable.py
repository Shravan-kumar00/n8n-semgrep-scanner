"""Sample - intentionally vulnerable Python service (for scanner demos)."""
import hashlib
import os
import pickle
import sqlite3
import subprocess
import tempfile

import jwt
import requests
import yaml
from flask import Flask, request

app = Flask(__name__)
DEBUG = True

DB_PASSWORD = "Sup3rS3cret!2026"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
DATABASE_URL = "postgresql://admin:Winter2026@db.internal:5432/orders"


@app.route("/export")
def export():
    name = request.args["name"]
    os.system("tar czf /tmp/" + name + ".tgz /data")
    subprocess.run(f"convert {name}.png out.pdf", shell=True)
    return "ok"


@app.route("/user")
def user():
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % request.args["name"])
    cur.execute(f"DELETE FROM sessions WHERE id = {request.args['sid']}")
    return str(cur.fetchall())


@app.route("/calc")
def calc():
    return str(eval(request.args["expr"]))


@app.route("/import", methods=["POST"])
def import_data():
    data = pickle.loads(request.data)
    config = yaml.load(request.form["config"])
    return str(data) + str(config)


def fetch_report():
    return requests.get("https://reports.internal/latest", verify=False).text


def read_token(token):
    return jwt.decode(token, options={"verify_signature": False})


def checksum(password):
    return hashlib.md5(password.encode()).hexdigest()


def scratch_file():
    return tempfile.mktemp()


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
