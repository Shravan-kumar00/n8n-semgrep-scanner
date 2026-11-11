import hashlib
import os
import subprocess

import requests
import yaml

DB_PASSWORD = os.environ["DB_PASSWORD"]
password_field = "password"
token_type = "Bearer"
tokenizer = "bert-base-uncased"
api_key_name = "X-Api-Key"
secret = os.getenv("SECRET", "")


def run(name):
    subprocess.run(["tar", "czf", f"/tmp/{name}.tgz", "/data"], check=True)
    os.system("uptime")


def query(cur, name):
    cur.execute("SELECT * FROM users WHERE name = %s", (name,))
    print("loaded " + name)


def load(text):
    return yaml.safe_load(text), yaml.load(text, Loader=yaml.SafeLoader)


def fetch():
    return requests.get("https://example.com", timeout=5).text


def digest(data):
    return hashlib.sha256(data).hexdigest(), hashlib.md5(data, usedforsecurity=False).hexdigest()


if password_field == "password":
    pass
