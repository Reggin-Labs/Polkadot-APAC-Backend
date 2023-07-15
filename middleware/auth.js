const jwt = require("jsonwebtoken");
require("dotenv").config();
const { stringToU8a, hexToU8a } = require("@polkadot/util");
const { signatureVerify } = require("@polkadot/util-crypto");

module.exports = function (req, res, next) {
  // Get token from header
  const token = req.header("x-auth-token");

  if (!token) {
    return res.status(401).json({
      msg: "No token, authorization denied",
    });
  } // Verify token

  const address = req.body.address;

  if (!address) {
    return res.status(401).json({
      msg: "No address, authorization denied",
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const sign = hexToU8a(decoded.sign);
    const message = stringToU8a(process.env.MESSAGE);
    const { isValid } = signatureVerify(message, sign, address);

    if (!isValid) {
      return res.status(401).json({ msg: "Invalid Signature" });
    }

    req.address = address;

    next();
  } catch (err) {
    res.status(401).json({
      msg: "Token is not valid",
    });
  }
};
