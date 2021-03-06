// const crypto = require("crypto");
// const async = require("async");
// const nodemailer = require("nodemailer");
// var User = require("./models/users");

module.exports = function(app, passport) {
  app.get("/", function(req, res) {
    res.render("index.ejs");
  });

  app.get("/login", function(req, res) {
    res.render("login.ejs", { message: req.flash("loginMessage") });
  });

  app.post(
    "/login",
    passport.authenticate("local-login", {
      successRedirect: "/profile", // redirect to the secure profile section
      failureRedirect: "/login", // redirect back to the signup page if there is an error
      failureFlash: true // allow flash messages
    })
  );

  app.get("/signup", function(req, res) {
    res.render("signup.ejs", { message: req.flash("signupMessage") });
  });

  app.post(
    "/signup",
    passport.authenticate("local-signup", {
      successRedirect: "/profile",
      failureFlash: true,
      failureRedirect: "/signup"
    })
  );

  app.get("/profile", isLoggedIn, function(req, res) {
    res.render("profile.ejs", {
      user: req.user
    });
  });

  app.get("/logout", function(req, res) {
    req.logout();
    res.redirect("/");
  });

  app.get(
    "/auth/google",
    passport.authenticate("google", { scope: ["profile", "email"] })
  );

  // the callback after google has authenticated the user
  app.get(
    "/auth/google/redirect",
    passport.authenticate("google", {
      successRedirect: "/profile",
      failureRedirect: "/"
    })
  );
};

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();

  res.redirect("/", { message: req.flash("signupMessage") });
}
