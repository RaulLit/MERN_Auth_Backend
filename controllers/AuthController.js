const User = require("../models/User");
const bcrypt = require("bcrypt");
const validator = require("validator");
const jwt = require("jsonwebtoken");

const createToken = (_id, name) => {
  return jwt.sign({ _id, name }, process.env.SECRET, { expiresIn: "7d" });
};

/**
 * Log a user in
 * @route /api/user/login
 * @method POST
 */
module.exports.loginUser = async (req, res) => {
  const { email, password } = req.body;
  try {
    // Validation
    if (!email || !password) throw Error("All fields are required");

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) throw Error(`User with email '${email}' not found`);

    // Match password
    const match = await bcrypt.compare(password, user.password);
    if (!match) throw Error("Incorrect password");

    // create a token
    const token = createToken(user._id, user.name);

    res.cookie("token", token, { httpOnly: true, sameSite: "none", secure: true });
    res.json({ name: user.name });
  } catch (err) {
    console.log(err.message);
    res.status(401).json({ error: err.message });
  }
};

/**
 * Sign up a user
 * @route /api/user/signup
 * @method POST
 */
module.exports.signupUser = async (req, res) => {
  const { name, email, password } = req.body;

  // strong password validation options
  const isStrongOptions = {
    minUppercase: 0,
    minSymbols: 0,
  };

  try {
    // Validation
    if (!email || !password || !name) throw Error("All fields are required");
    if (!validator.isEmail(email)) throw Error("Email is not valid");
    if (!validator.isStrongPassword(password, isStrongOptions))
      throw Error("Password not strong enough");

    // Check if email already registered
    const exist = await User.findOne({ email });
    if (exist) throw Error("Email already in use");

    // Hashing
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);

    const user = await User.create({ name, email, password: hash });

    // create a token
    const token = createToken(user._id, user.name);

    res.cookie("token", token, { httpOnly: true, sameSite: "none", secure: true });
    res.json({ name: user.name });
  } catch (err) {
    console.log(err.message);
    res.status(401).json({ error: err.message });
  }
};

/**
 * Logout a user
 * @route /api/user/logout
 * @method GET
 */
module.exports.logout = async (req, res) => {
  res
    .cookie("token", "", {
      httpOnly: true,
      expires: new Date(0),
      secure: true,
      sameSite: "none",
    })
    .json({ logout: true });
};

/**
 * Gets if a user is authenticated or not
 * @route /api/user/isLoggedIn
 * @method GET
 */
module.exports.isLoggedIn = async (req, res) => {
  try {
    const { token } = req.cookies;
    if (!token) throw Error("No token");

    const decoded = jwt.verify(token, process.env.SECRET, (err, result) => {
      if (err && err.name === "TokenExpiredError") return "Token expired";
      return result;
    });
    if (decoded === "Token expired") throw Error("Auth token expired");
    res.json({ name: decoded.name });
  } catch (err) {
    res.json({ status: "error", message: err.message });
  }
};

/**
 * Protects authenticated routes
 * @middleware
 */
module.exports.auth = (req, res, next) => {
  try {
    const token = req.cookies.token;
    if (!token) throw Error("Unauthorized");

    const decoded = jwt.verify(token, process.env.SECRET, (err, result) => {
      if (err && err.name === "TokenExpiredError") return "Token expired";
      return result;
    });
    if (decoded === "Token expired") throw Error("Auth token expired");
    req.user = decoded._id;
    next();
  } catch (error) {
    console.log(error);
    res.status(401).json({ error: error.message });
  }
};
