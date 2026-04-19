const express = require("express");
const bcrypt = require("bcrypt");
const path = require("path");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

// Model's
const userModel = require("./model/userModel");
const postModel = require("./model/postModel");

const app = express();

app.set("view engine", "ejs");

app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.get("/register", (req, res) => {
  res.render("index");
});

// User Create
app.post("/register", async (req, res) => {
  let { username, name, age, email, password } = req.body;
  const exitsUser = await userModel.findOne({ email });

  if (exitsUser) return res.status(500).send("User already exits!");

  bcrypt.genSalt(10, (err, salt) => {
    bcrypt.hash(password, salt, async (err, hash) => {
      const user = await userModel.create({
        username,
        name,
        age,
        email,
        password: hash,
      });

      const token = jwt.sign({ email: email, userid: user._id }, "SECRET_KEY");
      res.cookie("token", token);
      res.render("profile", { user });
    });
  });
});

// Login
app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  let { email, password } = req.body;

  const user = await userModel.findOne({ email });

  if (!user) return res.status(500).send("User not found!");

  bcrypt.compare(password, user.password, (err, result) => {
    if (result) {
      const token = jwt.sign({ email: email, userid: user._id }, "SECRET_KEY");
      res.cookie("token", token);
      res.status(200).redirect("/profile");
    } else {
      return res.status(500).send("Password does not match!");
    }
  });
});

// Logout
app.get("/logout", (req, res) => {
  // res.clearCookie("token");
  res.cookie("token", "");
  res.redirect("/login");
});

// Protected Route
const isLoggedIn = (req, res, next) => {
  if (req.cookies.token === "") {
    return res.send("You must be login first");
  } else {
    const data = jwt.verify(req.cookies.token, "SECRET_KEY");
    req.user = data;
    next();
  }
};

// Profile
app.get("/profile", isLoggedIn, async (req, res) => {
  const user = await userModel
    .findOne({ email: req.user.email })
    .populate("posts");
  res.render("profile", { user });
});

// Post
app.post("/post", isLoggedIn, async (req, res) => {
  const user = await userModel.findOne({ email: req.user.email });

  const content = req.body.content;

  const post = await postModel.create({
    user: user._id,
    content: content,
  });

  user.posts.push(post._id);
  await user.save();

  res.redirect("/profile");
});


// Server
app.listen(3000, () => {
  console.log("Server is running...");
});
