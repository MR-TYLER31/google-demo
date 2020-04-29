var express = require("express");
var app = express();
var port = process.env.PORT || 3000;
var mongoose = require("mongoose");
var passport = require("passport");
var flash = require("connect-flash");

var morgan = require("morgan");
var cookieParser = require("cookie-parser");
var bodyParser = require("body-parser");
var session = require("express-session");

// var configDB = require("./config/database.js");

// mongoose.connect(configDB.url);
require("./config/passport-setup")(passport);

app.use(morgan("dev")); // log every request to the console
app.use(cookieParser()); // read cookies (needed for auth)
app.use(bodyParser.urlencoded({ extended: false })); // get information from html forms

app.set("view engine", "ejs");

app.use(
  session({ resave: false, saveUninitialized: true, secret: "secretsession" })
); // session secret
app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions
app.use(flash());

mongoose.connect(process.env.MONGODB_URI || "mongodb://localhost/authodemo", {
  useNewUrlParser: true,
  useFindAndModify: false,
  useUnifiedTopology: true
});

require("./routes.js")(app, passport); // load our routes and pass in our app and fully configured passport

app.listen(port);
console.log("Server running on " + port);
