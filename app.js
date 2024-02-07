require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const saltRounds = 10;

const port = 3000;

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);

// app.set('trust proxy', 1)
app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}))

  app.use(passport.initialize());
  app.use(passport.session());

main().catch((err) => console.log(err));

async function main() {
  await mongoose.connect("mongodb://127.0.0.1:27017/userDB");
}

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
function(accessToken, refreshToken, profile, cb) {
  console.log(profile);

  User.findOrCreate({ googleId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));

passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID,
  clientSecret: process.env.FACEBOOK_APP_SECRET,
  callbackURL: "http://localhost:3000/auth/facebook/secrets"
},
function(accessToken, refreshToken, profile, cb) {
  User.findOrCreate({ facebookId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));

app.get("/", (req, res) => {
  res.render("Home");
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
});

app.get('/auth/facebook',
  passport.authenticate('facebook',{ scope: "email" })
);

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect('/secrets');
  });

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/secrets", (req, res) => {
  User.find({"secret": {$ne: null}})
  .then((foundUsers) => {
    if(foundUsers) {
      res.render("secrets" , {usersWithSecrets : foundUsers})
    }
  })
  .catch((err) => {
    console.log(err);
  })
});

app.get("/logout" , (req, res) => {
  req.logout((err) => {
    if (err) {
      console.log(err);
    }
    res.redirect("/");
  })
});

app.get("/submit", (req, res) => {
  if(req.isAuthenticated()){
    res.render("submit");
  }
  else{
    res.redirect("/login")
  }
})

app.post("/register", (req, res) => {
  
  User.register({username: req.body.username}, req.body.password)
  .then((user) => {
    passport.authenticate("local")(req, res, () => {
      res.redirect("/secrets");
    })
  })
  .catch((err) => {
    console.log(err);
    res.redirect("/register")
  })

});

app.post("/login", (req, res) => {
  
  const user = new User({
    username : req.body.username,
    password : req.body.password
  })

  req.login(user, (err) => {
    if(err) {
      console.log(err);
    }
    else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      })
    }
  })

});

app.post("/submit", (req, res) => {
  const submittedSecret = req.body.secret;
  console.log(submittedSecret);

  console.log(req.user._id);

  User.findById(req.user._id)
  .then((foundUser) => {
    console.log(foundUser);
    foundUser.secret = submittedSecret;
    foundUser.save();
    res.redirect("/secrets");
    console.log(foundUser);
  })
  .catch((err) => {
    console.log(err);
  })
})

app.listen(port, (req, res) => {
  console.log(`Server is running on Port ${port}`);
});
