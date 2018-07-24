const jwt = require('jwt-simple');
const config = require('../config');
const User = require ('../models/user');

function tokenForUser(user) {
  const timeStamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timeStamp }, config.secret);
}

exports.signin = function(req, res, next) {
  //user already supply email and pass, give user a token
  res.send({ token: tokenForUser(req.user) });
}

exports.signup = function(req, res, next) {
  const email = req.body.email;
  const password = req.body.password;

  if (!email || !password) {
    return res.status(422).send({error: 'Please provide an email and a password!'})
  }

  //see if if an email already exist
User.findOne({email: email}, function(err, existingUser) {
  if(err) {
    return next(err);
  }
   //if user email exist, return error
  if(existingUser) {
    return res.status(422).send({ error: 'Email is in use' });
  }
    //if email does not exist, create and save record
  const user =  new User({
    email: email,
    password: password
  })

  user.save(function(err) {
    if(err) {
      return next(err);
    }
      //respond to request that user was created
    res.json({ token: tokenForUser(user)});
  });
});

}