var session = require('express-session');
var passport = require('passport');
var { Strategy } = require('passport-openidconnect');

var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var bodyParser = require('body-parser');

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');

require('dotenv').config()

var app = express();


app.use(bodyParser.json({limit: '50mb'}));
app.use(bodyParser.urlencoded({limit: '50mb', extended: true}));

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: 'CanYouLookTheOtherWay',
  resave: false,
  saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

// set up passport
passport.use('oidc', new Strategy({
  issuer: `https://${process.env.OKTA_DOMAIN}/oauth2/default`,
  authorizationURL: `https://${process.env.OKTA_DOMAIN}/oauth2/default/v1/authorize`,
  tokenURL: `https://${process.env.OKTA_DOMAIN}/oauth2/default/v1/token`,
  userInfoURL: `https://${process.env.OKTA_DOMAIN}/oauth2/default/v1/userinfo`,
  clientID: `${process.env.OKTA_CLIENT_ID}`,
  clientSecret: `${process.env.OKTA_SECRET}`,
  callbackURL: `${process.env.CALLBACK_URL}`,
  scope: 'openid profile'
}, (issuer, profile, done) => {
  return done(null, profile);
}));

app.use('/signin', passport.authenticate('oidc'));

app.post('/signout', (req, res) => {
   req.logout(err => {
      if (err) { return next(err); }
      let params = {
         id_token_hint: '',
         post_signout_redirect_uri: 'http://localhost:3000/'
      }
      res.redirect('/');
      req.session.destroy();
   });
});

app.use('/authorization-code/callback',
  passport.authenticate('oidc', { failureMessage: true, failWithError: true }),
  (req, res) => {
    res.redirect('/profile');
  }
);

app.use('/profile', (req, res) => {
  res.render('profile', { user: req.user });
});

passport.serializeUser((user, next) => {
  next(null, user);
});

passport.deserializeUser((obj, next) => {
  next(null, obj);
});


app.use('/', indexRouter);
app.use('/users', usersRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
