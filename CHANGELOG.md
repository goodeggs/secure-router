# [v3.0.0](https://github.com/goodeggs/secure-router/compare/v2.1.1...v3.0.0)

- If there is more than one bouncer that `DENY`s, the first one that is encountered
  is the one that will determine the response of the request.
  
- **BEWARE** - Bouncers are now expected to return a promise that resolves with an object
  that has a `middleware` property. Versions of `goodeggs-authentication-tokens` [<10.0.0](https://github.com/goodeggs/goodeggs-authentication-tokens/blob/master/CHANGELOG.md#v1000)
  use an earlier version of `sercure-router` in which `Router.denyWith` returns an object without the property.
  
  That means in addition to bumping secure-router you *must* bump any of the following module used in the project that use secure-router: 
  * `goodeggs-server>15`
  * `goodeggs-authentication-tokens>10`
  * `goodeggs-employee-roles>6`  

# [v2.0.0](https://github.com/goodeggs/secure-router/compare/v1.2.1...v2.0.0)

- `AUTHENTICATE`, `AUTHORIZE`, and `DENY` are now constants that live on the
  `SecureRouter` object.
- You can send custom responses when bouncing a request, with
  `SecureRouter.denyWith()`

```js
const bouncer = function (req, res) {
  getSecurityClearanceLevel(req.user.id)
  .then(function (level) {
    if (level === 'TOP SECRET') return SecureRouter.AUTHORIZE;
    else return SecureRouter.denyWith({
      statusCode: 404,
      payload: 'Nothing to see here, move along.'
    });
  });
}
```
