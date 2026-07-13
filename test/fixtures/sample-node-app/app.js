// Intentionally vulnerable sample for Patronus end-to-end tests.
// This file is NOT production code. Do not copy these patterns.

const express = require('express');
const cp = require('child_process');
const app = express();

app.use(express.json());

// Command injection via child_process with user input.
app.get('/ping', (req, res) => {
  const host = req.query.host;
  cp.exec('ping ' + host, (err, stdout) => {
    res.send(stdout);
  });
});

// eval on user-controlled input.
app.post('/calc', (req, res) => {
  const result = eval(req.body.expr);
  res.json({ result });
});

// Overly permissive CORS.
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  next();
});

app.listen(3000);

module.exports = app;
