const { ack } = require("__LOGGER_REQUIRE__");
export default function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).end();
    return;
  }
  ack(req, res);
}
