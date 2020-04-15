const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const { ExtractJwt } = require('passport-jwt');
const { JWT_SECRET } = require('./config');
const User = require('./models/user');
const LocalStragegy = require('passport-local').Strategy;
const GooglePlusTokenStrategy = require('passport-google-plus-token');
const FacebookTokenStrategy = require('passport-facebook-token');
const config = require('./config');

// JSON WEB TOKENS STRATEGY
passport.use(new JwtStrategy({
    jwtFromRequest: ExtractJwt.fromHeader('authorization'),
    secretOrKey: JWT_SECRET
}, async (payload, done) => {
    try {
        // Find the user specified in token
        const user = await User.findById(payload.sub);
        // If user doesn't exists, handle it
        if (!user) {
            return done(null, false);
        }
        // Otherwise, return the user
        done(null, user);
    } catch (err) {
        done(err, false);
    }
}));

// GOOGLE OAUTH STRATEGY
passport.use('googleToken', new GooglePlusTokenStrategy({
    clientID: config.oauth.google.clientID,
    clientSecret: config.oauth.google.clientSecret
}, async (accessToken, refreshToken, profile, done) => {
    try {
        console.log('accessToken', accessToken);
        console.log('refreshToken', refreshToken);
        console.log('profile', profile);

        // Check whether this currrent user exists in our DB
        const existingUser = await User.findOne({ "google.id": profile.id });
        if (existingUser) {
            console.log('User already exists in our DB');
            return done(null, existingUser);
        }

        console.log('User doesn\'t exists, we\'re creating a new one');

        // If new account
        const newUser = new User({
            method: 'google',
            google: {
                id: profile.id,
                email: profile.emails[0].value
            }
        });
        await newUser.save();
        done(null, newUser);
    } catch (err) {
        done(err, false, err.message);
    }
}));

// FACEBOOK OAUTH STRATEGY
passport.use('facebookToken', new FacebookTokenStrategy({
    clientID: config.oauth.facebook.clientID,
    clientSecret: config.oauth.facebook.clientSecret
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const existingUser = await User.findOne({ "facebook.id": profile.id });
        if (existingUser) {
            done(null, existingUser);
        }
        const newUser = new User({
            method: 'facebook',
            facebook: {
                id: profile.id,
                email: profile.emails[0].value
            }
        });
        await newUser.save();
        done(null, newUser);
    } catch (err) {
        console.log(err.message);
        done(err, false, err.message);
    }
}));

// LOCAL STRATEGY
passport.use(new LocalStragegy({
    usernameField: 'email'
}, async (email, password, done) => {
    try {
        // Find the user given the email
        const user = await User.findOne({ "local.email": email });
        // If not, handle it
        if (!user) {
            return done(null, false);
        }
        // Check if the password is correct
        const isMatch = await user.isValidPassword(password);
        // If not, handle it
        if (!isMatch) {
            return done(null, false);
        }
        // Otherwise, return the user
        done(null, user);
    } catch (err) {
        done(err, false);
    }
}));