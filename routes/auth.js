const express = require("express");
const router = express.Router();
const {
  loginUser,
  signupUser,
  logout,
  isLoggedIn,
} = require("../controllers/AuthController");

router.post("/login", loginUser);
router.post("/signup", signupUser);
router.get("/logout", logout);
router.get("/isLoggedIn", isLoggedIn);

module.exports = router;
