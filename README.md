#Passport CAS Stragety

Strategy for [Passport](passportjs.org) authentication utilizing [CAS](cas.jasig.org). 
In a nutshell, this module will redirect a user to your CAS login page as
needed and validate the returned CAS ticket to obtain the username.

##Sample Usage
``` javascript
var cas = require('passport-cas')
, express = require('express')
, passport = require('passport');

/* configure the strategy */
passport.use(new cas.Strategy({
    CAS: {
        root: 'yourcashost.com',
        validateUri: '/cas/serviceValidate',
        loginUri: '/cas/login'
    }
}, function(user, done){
    /* user will contain the user identifier returned by CAS */
    return done(null, user);
}));

/* route using CAS */
app.get("/login", passport.authenticate('cas'), function(req, res){
    res.send("Logged in user: " + req.user);
}
```