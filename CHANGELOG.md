# [v3.0.0](https://github.com/goodeggs/secure-router/compare/v2.1.1...v3.0.0)

- If there is more than one bouncer that `DENY`s, the first one that is encountered
  is the one that will determine the response of the request.

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
