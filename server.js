require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const userRoutes = require("./routes/auth");

// express app
const app = express();

// Initialise middleware
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: [process.env.CLIENT_URL],
    methods: ["GET", "POST", "DELETE", "PUT"],
    credentials: true,
  })
);

app.use((req, res, next) => {
  console.log(req.path, req.method);
  next();
});

// Routes
app.use("/api", userRoutes);

// Connect to db
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    // Start server
    app.listen(process.env.PORT || 4000, () => {
      console.log("Connected to db & running on port", process.env.PORT || 4000);
    });
  })
  .catch((err) => console.log(err));
