//jshint esversion:6
require('dotenv').config()
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
// const bcrypt = require('bcrypt');
// const saltRounds = 10;
// const md5 = require('md5');
// const encrypt = require('mongoose-encryption');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({
    secret: 'Our little secret',
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

main().catch(err => console.log(err));

async function main() {
    await mongoose.connect('mongodb://127.0.0.1:27017/userDB');

    // use `await mongoose.connect('mongodb://user:password@127.0.0.1:27017/userDB');` if your database has auth enabled
}

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password']});

const User = mongoose.model('User', userSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, {
            id: user.id,
            username: user.username,
            picture: user.picture
        });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});



passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
},
    async function (accessToken, refreshToken, profile, done) {
        try {
            // console.log(profile);
            // Find or create user in your database
            let user = await User.findOne({
                googleId: profile.id
            });
            if (!user) {
                // Create new user in database
                const username = Array.isArray(profile.emails) && profile.emails.length > 0 ? profile.emails[0].value.split('@')[0] : '';
                const newUser = new User({
                    username: profile.displayName,
                    googleId: profile.id
                });
                user = await newUser.save();
            }
            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }
    // async function (accessToken, refreshToken, profile, cb) {
    //     await User.findOrCreate({ googleId: profile.id }, function (err, user) {
    //         return cb(err, user);
    //     });
    // }
));


app.get('/', async (req, res) => {
    res.render('home');
});

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] })
);

app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    });

app.get('/login', async (req, res) => {
    res.render('login');
});

app.get('/register', async (req, res) => {
    res.render('register');
});


app.get("/secrets", async (req, res) => {
    let temp3 = await User.find({"secret": {$ne: null}});
    if(temp3){
        res.render('secrets', { userWithSecrets : temp3});
    }
});

app.get("/logout", async (req, res) => {
    req.logout(function (err) {
        if (err) { return next(err); }
        res.redirect('/');
    });
});


app.get("/submit", async (req, res) => {
    if (req.isAuthenticated()) {
        res.render('submit');
    } else {
        res.redirect('/login');
    }
});

app.post("/submit", async (req, res) => {
    const submittedSecret = req.body.secret;
    // console.log(req.user);
    let temp2 = await User.findOne({_id: req.user.id});
    if(temp2) {
        temp2.secret = submittedSecret;
        temp2.save();
        res.redirect("/secrets");
    }

});

app.post('/register', async (req, res) => {

    User.register({ username: req.body.username }, req.body.password, function (err, user) {
        if (err) {
            console.log(err);
            res.redirect('/register');
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets")
            });
        }
    })

    // bcrypt.hash(req.body.password, saltRounds, async function(err, hash) {
    //     const newUser = new User({
    //         email: req.body.username,
    //         // password: md5(req.body.password)
    //         password: hash
    //     });

    //     let temp = await newUser.save();
    //     if(!temp){
    //         console.log(temp);
    //     }else{
    //         res.render('secrets');
    //     }
    // });
});

app.post("/login", async (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function (err) {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets")
            });
        }
    });

    // const username = req.body.username;
    // // const password = md5(req.body.password);
    // const password = req.body.password;

    // let temp1 = await User.findOne({ email: username});
    // if(!temp1){
    //     console.log(temp1);
    // }else{
    //     bcrypt.compare(password, temp1.password, function(err, result) {
    //         if(result === true){
    //             res.render('secrets');
    //         }
    //     });
    // }
});

app.listen(3000, function () {
    console.log('listening on port 3000');
});



