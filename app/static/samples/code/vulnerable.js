// Sample - intentionally vulnerable Node.js API (for scanner demos)
const express = require("express");
const cp = require("child_process");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const serialize = require("node-serialize");
const { Pool } = require("pg");

const app = express();
const db = new Pool();
const apiKey = "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY";
const config = { password: "Adm1n-Passw0rd", host: "db.internal" };
const agent = new (require("https").Agent)({ rejectUnauthorized: false });

app.use(cors({ origin: "*" }));

app.get("/ping", (req, res) => {
  cp.exec("ping -c 1 " + req.query.host, (err, out) => res.send(out));
});

app.get("/users", async (req, res) => {
  const rows = await db.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);
  const more = await db.query("SELECT * FROM orders WHERE id = " + req.query.id);
  res.json({ rows, more });
});

app.post("/calc", (req, res) => res.send(String(eval(req.body.expr))));

app.post("/login", (req, res) => {
  const token = jwt.sign({ user: req.body.user }, "my-super-secret-key");
  res.json({ token, hash: crypto.createHash("md5").update(req.body.password).digest("hex") });
});

app.post("/restore", (req, res) => res.json(serialize.unserialize(req.body.session)));

function renderGreeting(name) {
  document.getElementById("greeting").innerHTML = "<b>Hello " + name + "</b>";
}

module.exports = { app, agent, config, apiKey, renderGreeting };
