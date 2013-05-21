var crypto = require('crypto');

var request = require('request');
var async = require('async');

module.exports = function() {
  function verify(token, certSource, callback) {

    parsedjwt = parseJWT(token);

    var verifier = crypto.createVerify("sha256");

    keyid = parsedjwt.header.kid;
    verifier.update(parsedjwt.signedPart);


    retrieveCertificates(certSource, keyid, function(cert) {
      console.log(cert);
      var result = verifier.verify(cert, new Buffer(parsedjwt.signature.replace("-", "+").replace("_", "/"), "base64"));
      console.log(result);
      callback(parsedjwt, undefined);


    });



  }

  function parseJWT(token) {
    var jwtParts = token.split('.');

    var encodedHeader = jwtParts[0];
    var encodedClaims = jwtParts[1];
    var encodedSignature = jwtParts[2];

    var decodedHeader = new Buffer(encodedHeader, 'base64').toString('utf8');
    var decodedClaims = new Buffer(encodedClaims, 'base64').toString('utf8');

    return {
      header: JSON.parse(decodedHeader),
      claims: JSON.parse(decodedClaims),
      signature: encodedSignature,
      signedPart: encodedHeader + "." + encodedClaims
    };
  }


  function retrieveCertificates(certSource, keyid, callback) {

    request(certSource, function(error, response, body) {
      if (!error && response.statusCode == 200) {
        console.log(JSON.parse(body)[keyid]);
        callback(JSON.parse(body)[keyid]);
      }
    });
  };


  return {
    verify: verify
  };
}();