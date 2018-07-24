const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const localStrategy = require('passport-local');

//create local strategy\
const localOptions = { usernameField: 'email' };
const localLogin = new localStrategy(localOptions, function(email, password, done) {
  //verify email and password, call done if it is correct
  //if not, call done with false
  User.findOne({email: email}, (err, user) => {
    if(err) { return done(err)  };
    if(!user) { return done(null, false); }

    //compare passwords - is password equal the user.password?
    user.comparePassword(password, function(err, isMatch) {
      if(err) { return done(err); }
      if(!isMatch) { return done(null, false); }

      return done(null, user);
    });
  });
});

//Is our user logged in?
//sestup options for JWT strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
};

//create JWT strategy
const jwtLogin = new JwtStrategy(jwtOptions, (payload, done) => {
  //see if user exist in DB
  //if it does, call 'done, otherwise
  //call done without a user object
  User.findById(payload.sub, function(err, user) {
    if (err) { return done(err, false); }

    if (user) {
      done(null, user );
    } else {
      done(null, false);
    }
  });
});

//tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);