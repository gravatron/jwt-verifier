var should = require('should')

var uut = require('../lib/jwt-verifier');

describe('jwt-verifier', function() {
  describe('#verify()', function() {
    it.skip('should return the parsed JWT if it validated correctly', function(done) {

      var token = 'eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.';
      var certSource = 'https://www.googleapis.com/oauth2/v1/certs';

      uut.verify(token, certSource, function(decodedJwt, err) {
        should.not.exist(err);
        should.exist(decodedJwt);

        expectedHeader = {
          'alg': 'none'
        };
        expectedClaims = {
          'iss': 'joe',
          'exp': 1300819380,
          'http://example.com/is_root': true
        };
        expectedSignature = '';

        decodedJwt.header.should.eql(expectedHeader);
        decodedJwt.claims.should.eql(expectedClaims);

        done();
      });
    })

    it('should return the parsed JWT if it validated correctly', function(done) {

      var token = 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjgzYmRkM2IzNjA1MTRlN2FmMTc0ZGVkNWI0NDVjYWYxNTc0YzEwYTkifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiaWQiOiIxMDg0MzY4NzQ2MDQxMjU3Njc3OTgiLCJzdWIiOiIxMDg0MzY4NzQ2MDQxMjU3Njc3OTgiLCJhdWQiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJ0b2tlbl9oYXNoIjoiTW1BS0o1V0UxRkQ1WHlCVlFaQlNqZyIsImF0X2hhc2giOiJNbUFLSjVXRTFGRDVYeUJWUVpCU2pnIiwiY2lkIjoiNDA3NDA4NzE4MTkyLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiYXpwIjoiNDA3NDA4NzE4MTkyLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiaWF0IjoxMzY5MTMyNzQ3LCJleHAiOjEzNjkxMzY2NDd9.Fk0B9GRDRTy6cnl26yk3WHtqxlQDyxGljDqSs0Tfk74lvYB-k7Tc5vscsUnH1Pamhl3s0TSae0N1dK0lfFXNPm-1-Fexmll0kqIByv8Go8F-1XQmxEcaR90kCo05Uls1MjZMYINE16LlytQZcO3PIzeiixcNAiQtexbaB1H6RV8';
      var certSource = 'https://www.googleapis.com/oauth2/v1/certs';

      uut.verify(token, certSource, function(decodedJwt, err) {
        should.not.exist(err);
        should.exist(decodedJwt);

        expectedHeader = {
          'alg': 'RS256',
          'kid': '83bdd3b360514e7af174ded5b445caf1574c10a9'
        };
        expectedClaims = {
          'iss': 'accounts.google.com',
          'id': '108436874604125767798',
          'sub': '108436874604125767798',
          'aud': '407408718192.apps.googleusercontent.com',
          'token_hash': 'MmAKJ5WE1FD5XyBVQZBSjg',
          'at_hash': 'MmAKJ5WE1FD5XyBVQZBSjg',
          'cid': '407408718192.apps.googleusercontent.com',
          'azp': '407408718192.apps.googleusercontent.com',
          'iat': 1369132747,
          'exp': 1369136647
        };
        expectedSignature = '';

        decodedJwt.header.should.eql(expectedHeader);
        decodedJwt.claims.should.eql(expectedClaims);
        decodedJwt.signature = 'Fk0B9GRDRTy6cnl26yk3WHtqxlQDyxGljDqSs0Tfk74lvYB-k7Tc5vscsUnH1Pamhl3s0TSae0N1dK0lfFXNPm-1-Fexmll0kqIByv8Go8F-1XQmxEcaR90kCo05Uls1MjZMYINE16LlytQZcO3PIzeiixcNAiQtexbaB1H6RV8';

        done();
      });
    })
  })
})