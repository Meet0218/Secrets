require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');

/// google oauth
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

/// modules used for cookies
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

// Hash function 3rd level security
// const md5 = require("md5");


/// bcrypt 4th level security
// const bcrypt = require("bcrypt");
// const saltRounds = 10;

/// This is for mongoose encryption this is 2nd level security
// const encrypt = require("mongoose-encryption");

const app = express();

app.set('view engine', 'ejs');
mongoose.set('strictQuery', false);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

/// initialization of cookies
app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/userDB", { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

/// plugin for passportLocalMongoose
userSchema.plugin(passportLocalMongoose);

/// plugin for findorcreate-mongoose
userSchema.plugin(findOrCreate);


/// This is encryption method created using mongoose encryption
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

const User = new mongoose.model("User", userSchema);

/// passport serialize and deserialize cookies
passport.use(User.createStrategy());


// Serialize and ddeserializing users
passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

/// google strategy implement
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

app.get("/", function (req, res) {
    res.render("home");
});

/// authenticate user from google
app.get("/auth/google",
    passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets",
    passport.authenticate('google', { failureRedirect: "/login" }),
    function (req, res) {
        // Successful authentication, redirect to secrets.
        res.redirect("/secrets");
    });

app.get("/login", function (req, res) {
    res.render("login");
});

app.get("/register", function (req, res) {
    res.render("register");
});

app.get("/secrets", function (req, res) {
    User.find({ "secret": { $ne: null } }, function (err, foundUsers) {
        if (err) {
            console.log(err);
        } else {
            if (foundUsers) {
                res.render("secrets", { usersWithSecrets: foundUsers });
            }
        }
    });
});

app.get("/submit", function (req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
})

app.get("/logout", function (req, res) {
    req.logout(function (err) {
        if (err) {
            console.log(err);
        }
    });
    res.redirect("/");
});

app.post("/register", function (req, res) {

    // /// Secured using bcrypt
    // bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
    //     const newUser = new User({
    //         email: req.body.username,
    //         /// Password for normal purpose
    //         // password: req.body.password

    //         /// md5 password
    //         // password: md5(req.body.password)

    //         /// Password for bcrypt
    //         password: hash
    //     });

    //     newUser.save(function (err) {
    //         if (!err) {
    //             res.render("secrets");
    //         } else {
    //             console.log(err);
    //         }
    //     });
    // });



    //// registration route created for cookie purpose
    User.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login", function (req, res) {
    // const username = req.body.username;

    // /// md5 password
    // // const password = md5(req.body.password);

    // // bcrypt and normal password
    // const password = req.body.password;

    // User.findOne({ email: username }, function (err, foundUser) {
    //     if (err) {
    //         console.log(err);
    //     } else {
    //         if (foundUser) {
    //             bcrypt.compare(password, foundUser.password, function (err, result) {
    //                 if (result == true) {
    //                     res.render("secrets");
    //                 }
    //             });
    //         }
    //     }
    // });


    //// login route using cookies
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function (err) {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/submit", function (req, res) {
    const submittedSecret = req.body.secret;

    //Once the user is authenticated and their session gets saved, their user details are saved to req.user.
    // console.log(req.user.id);

    User.findById(req.user.id, function (err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save(function () {
                    res.redirect("/secrets");
                });
            }
        }
    });
});



app.listen(3000, function () {
    console.log("Server started on port 3000");
});