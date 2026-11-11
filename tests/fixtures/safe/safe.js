const { execFile } = require("child_process");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const password = process.env.DB_PASSWORD;
const passwordField = "password";
const tokenType = "Bearer";
const re = /ab+c/;
const match = re.exec(input);

function run(file) {
  execFile("convert", [file, "out.pdf"]);
}

async function users(db, name) {
  console.log("loading " + name);
  return db.query("SELECT * FROM users WHERE name = $1", [name]);
}

function sign(user) {
  return jwt.sign({ user }, process.env.JWT_SECRET);
}

function show(el, text) {
  el.textContent = text;
  el.innerHTML = "<b>static</b>";
  return crypto.createHash("sha256").update(text).digest("hex");
}

module.exports = { run, users, sign, show, password, passwordField, tokenType, match };
