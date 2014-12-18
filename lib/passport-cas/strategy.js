/* 
 * Implementation of a Passport strategy using CAS.
 */

var passport = require('passport')
, util = require('util')
, https = require('https')
, xml2js = require('xml2js');

/* Strategy constructor 
 * 
 * Options:
 *  - 'CAS.root'        Base URL of your CAS server, e.g. "https://cas.example.com"
 *  - 'CAS.loginUri'    Path to CAS login endpoint, e.g. "/login"
 *  - 'CAS.validateUri' Path to CAS validation endpoint, e.g. "/validate"
 *  
 * Parameters:
 *  
 *  @param {Object} options
 *  @param {Function} verify
 *  @api public
 */



function Strategy(options, verify){
    if (!options.CAS.root) throw new Error('You must specify a CAS root.');
    passport.Strategy.call(this);
    this.name = 'cas';
    this._verify = verify;
    this._casRoot = options.CAS.root;
    this._loginUri = options.CAS.loginUri;
    this._validateUri = options.CAS.validateUri;
    
}

/*
 * Inherit from passport.Strategy
 */
util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req){
    
    // rebuild the requested URL
    var myUrl = req.protocol + "://"
    + req.get('host'); //+ (port == 80 || port == 443 ? '' : ':' + port) 
                
    
    /**
     * If a ticketid is present, we've already been authenticated. Proceed
     * to validate the ticket and log in the user.
     **/
    var self = this;
    if (req.query && req.query['ticket']){
        var port = req.app.settings.port;
        var opts = {
            host: self._casRoot.replace(/^((http|https):\/\/)/, ''), //strip the protocol if present
            path: self._validateUri + '?service=' + myUrl + req.path + '&ticket=' + req.query['ticket'],
            method: 'GET'
        };
        var vreq = https.request(opts, function(vres){
            var validationResult = "";
            vres.on('data', function(chunk){
                validationResult += chunk;
            });
            
            vres.on('end', function(){
                //validate the response
                
                xml2js.parseString(validationResult, function(err, parsed){
                    console.log(JSON.stringify(parsed));
                    if (parsed['cas:serviceResponse']['cas:authenticationSuccess']){
                        /* We've succeeded in logging in, get the identifier */
                        self._verify(parsed['cas:serviceResponse']['cas:authenticationSuccess'][0]['cas:user'][0],
                            function(err, user, info){
                                if (err) { return self.error(err);}
                                if (!user) return self.fail(info);
                                self.success(user, info);
                            });
                    }
                })
                
            });
            
        }).end();
    }
    
    /**
     * If not, redirect to CAS login
     */
    else {
        self.redirect('https://' + self._casRoot + self._loginUri + '?service=' + myUrl + req.originalUrl);
    }

}

module.exports = Strategy;