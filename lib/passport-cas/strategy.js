/*
 * Implementation of a Passport strategy using CAS.
 */

var passport = require('passport'),
    util = require('util'),
    https = require('https'),
    xml2js = require('xml2js'),
    xpath = require('xml2js-xpath'),
    url = require('url'),
    uuid = require('node-uuid'),
    moment = require('moment'),
    request = require('request');

/* Strategy constructor
 *
 * Options:
 *  - 'CAS.root'        Base URL of your CAS server, e.g. "https://cas.example.com"
 *  - 'CAS.loginUri'    Path to CAS login endpoint, e.g. "/login"
 *  - 'CAS.validateUri' Path to CAS validation endpoint, e.g. "/validate"
 *
 * Note: if using the SAML validate URI, the user returned to the verfy callback
 * will be an object with two properties: id (the username) and affils (an array
 * of affiliations). The standard CAS validate URI will simply return a string.
 *
 * Parameters:
 *
 *  @param {Object} options
 *  @param {Function} verify
 *  @api public
 */



function Strategy(options, verify) {
    if (!options.CAS.root) throw new Error('You must specify a CAS root.');
    passport.Strategy.call(this);
    this.name = 'cas';
    this._verify = verify;
    this._casRoot = options.CAS.root;
    this._loginUri = options.CAS.loginUri;
    this._validateUri = options.CAS.validateUri;
    this._debug = options.debug;

}

/*
 * Inherit from passport.Strategy
 */
util.inherits(Strategy, passport.Strategy);

Strategy.prototype.authenticate = function(req) {

    // rebuild the requested URL root, forcing https protocol
    var myUrl = "https://" + req.get('host'); //+ (port == 80 || port == 443 ? '' : ':' + port)

    /**
     * If a ticketid is present, we've already been authenticated. Proceed
     * to validate the ticket and log in the user.
     **/
    var self = this;
    if (req.query && req.query['ticket']) {
        //assemble service URL, stripping out ticket parameter
        var svc = url.parse(myUrl + req.originalUrl, true);
        delete svc.query.ticket;
        svc.search = null;
        var service = url.format(svc);
        //var port = req.app.settings.port;

        var isSaml = self._validateUri.endsWith('samlValidate');
        var opts = createValidateRequest(isSaml, req.query['ticket'], service);

        //set path based on validation endpoint
        /*
        var pformat = '%s?%s=%s&%s=%s';
        var path = util.format(pformat,
            self._validateUri,
            'service',
            service,
            'ticket',
            req.query['ticket']);
        console.log(path);
        var opts = {
            host: self._casRoot.replace(/^((http|https):\/\/)/, ''), //strip the protocol if present
            path: path, //self._validateUri + '?service=' + service + '&ticket=' + req.query['ticket'],
            method: 'GET'
        };

        if (self._debug) {
            console.log("CAS Debug: ");
            console.log(opts);
        }
        */
        request(opts, function(err, response, validationResult){
          //validate the response
          console.log(validationResult);
          xml2js.parseString(validationResult, {tagNameProcessors: [xml2js.processors.stripPrefix]}, function(err, parsed) {
            if (err) console.log(err);
            console.log(util.inspect(parsed, false, null));
              if (self._debug) console.log(JSON.stringify(parsed));
                if (isSaml){
                  if (xpath.evalFirst(parsed, "//StatusCode", "Value").endsWith('Success')){
                    var user = {id: xpath.evalFirst(parsed, "//Subject/NameIdentifier")};
                    user.affils = xpath.find(parsed, "//Attribute[@AttributeName='affiliation']/AttributeValue")
                      .map(function(val){
                        return val._;
                      });
                      self._verify(user, function(err, user, info){
                        if (err) return self.error(err);
                        if (!user) return self.fail(info);
                        self.success(user, info);
                      })
                  }

                }
                else {
                  if (parsed['serviceResponse']['authenticationSuccess']) {
                      /* We've succeeded in logging in, get the identifier */
                      self._verify(parsed['serviceResponse']['authenticationSuccess'][0]['user'][0],
                          function(err, user, info) {
                              if (err) {
                                  return self.error(err);
                              }
                              if (!user) return self.fail(info);
                              self.success(user, info);
                          });
                  }
                }

          });
        });

    }

    /**
     * If not, redirect to CAS login
     */
    else {
        if (self._debug) console.log('Redirecting to CAS with URL: ' + 'https://' + self._casRoot + self._loginUri + '?service=' + myUrl + req.originalUrl);
        self.redirect('https://' + self._casRoot + self._loginUri + '?service=' + myUrl + req.originalUrl);
    }

    function createValidateRequest(isSaml, ticketID, service){
      var host = self._casRoot.replace(/^((http|https):\/\/)/, ''); //strip the protocol if present
      if (!isSaml){
        return {
            uri: 'https://' + host + self._validateUri,
            qs: {
              service: service,
              ticket: ticketID
            },
            method: 'GET'
        };
      }
      else {
        var SOAP = '<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/">' +
            '<SOAP-ENV:Header/>' +
              '<SOAP-ENV:Body>' +
                  '<samlp:Request xmlns:samlp="urn:oasis:names:tc:SAML:1.0:protocol" MajorVersion="1" MinorVersion="1" RequestID="%s" IssueInstant="%s">' +
                        '<samlp:AssertionArtifact>%s</samlp:AssertionArtifact>' +
            	  '</samlp:Request>' +
              '</SOAP-ENV:Body>' +
          '</SOAP-ENV:Envelope>';
        var body = util.format(SOAP, uuid.v1(), moment().utc().toISOString(), ticketID);
        return {
          uri: 'https://' + host + self._validateUri,
          qs: {
            TARGET: service
          },
          method: 'POST',
          body: body
        }
      }
    }

}



module.exports = Strategy;
