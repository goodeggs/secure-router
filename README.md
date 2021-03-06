# Secure Router

[![Build
Status](https://travis-ci.org/goodeggs/secure-router.svg?branch=master)](https://travis-ci.org/goodeggs/secure-router)

This node module implements a replacement for the `Router` that comes with
[Express][express]. It provides a stricter security model, making your
endpoints default to returning [`401 Unauthorized`][rfc401] or [`403
Forbidden`][rfc403] unless they have explicitly been **authenticated** and
**authorized**.

This module helps you avoid situations where you set up a route but forget
to add security middleware to it, leaving it unintentionally
world-readable/writeable. Using it is easy:

```javascript
import express from 'express';
import SecureRouter from 'secure-router';

const app = express();
const router = new SecureRouter();
router.bounceRequests();
app.use(router);

router.secureEndpoint({
  method: 'GET',
  path: '/the-crown-jewels',
  bouncers: [
    ((req) => if (req.user) return SecureRouter.AUTHENTICATE),
    ((req) => if (req.user.isRoyalty) return SecureRouter.AUTHORIZE),
  ],
  middleware (req, res) {
    req.send(theCrownJewels)
  },
});

/* OR */

secretRouter = router.secureSubpath({
  path: '/secrets',
  bouncers: [
    ((req) => if (req.user) return SecureRouter.AUTHENTICATE),
    ((req) => if (req.user.classification === 'MI6') return SecureRouter.AUTHORIZE),
    ((req) => if (req.user.number === '006') return return SecureRouter.DENY),
  ],
});

secretRouter.get('/mission-briefs', (req, res) => res.send(nextMission));
```

[rfc401]: https://httpstatuses.com/401
[rfc403]: https://httpstatuses.com/403
[express]: https://expressjs.com/

## Bouncers

You can define an arbitrary number of `bouncers` on routes, paths, or entire
routers.

Any bouncer can explicitly `DENY`, `AUTHENTICATE`, or `AUTHORIZE` a request for
a path for which that bouncer has been defined. This can be done asynchronously,
using a promise.

If any bouncer has elected to `DENY`, the request immediately short-circuits
with a `401` status.

If no bouncer has elected to `AUTHENTICATE`, the request immediately
short-circuits with a `401` status.

If no bouncer has elected to `AUTHORIZE`, the request immediately
short-circuits with a `403` status.

### Bouncer functions

All bouncers are individual functions, that accept a `req` and a `res` argument
(this is the same `req` that an express middleware receives), and return a
promise.  If the promise resolves to anything other than `SecureRouter.DENY`,
`SecureRouter.AUTHENTICATE`, `SecureRouter.AUTHORIZE`, or the result of
`SecureRouter.denyWith()`, the bouncer is ignored.

Example:

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

### `denyWith(<middleware|response>)`

Returns a bouncer response that will cause the bouncer to deny the request,
and will edit the response to whatever you specify. Takes either a function or
a configuration object.

- `middleware`: `function(req, res, next)`, is parsed like any other express middleware.
- `response.statusCode`: `number`, changes the statusCode of the response.
- `response.payload`: one of the following:
  - `string`, is sent in the body of the response.
  - `object`, is sent in the body of the response.
  
Examples:

```js
// with middleware
SecureRouter.denyWith(function (req, res, next) {
  // assuming AuthenticationError is defined elsewhere in your app
  // and handled later in another middleware that comes after bounceRequests
  return next(new AuthenticationError('Provide a site_token cookie!'));
}

// with a configuration object
SecureRouter.denyWith({
  statusCode: 404,
  payload: 'Nothing to see here, move along.'
});
```

### Defining bouncers on individual endpoints

Use the `secureEndpoint` method:

```js
router.secureEndpoint({
  method: 'GET',
  path: '/the-crown-jewels',
  bouncers: [bouncer1, bouncer2],
  middleware (req, res) {
    req.send(theCrownJewels);
  },
});
```

- **`method`**: `GET`, `POST`, `PUT`, `DELETE`, etc...
- **`path`**: appended to the path of the current router
- **`bouncers`**: list of bouncers. Alternatively, use **`bouncer`** to pass
  only one bouncer
- **`bouncer`**: individual bouncer. Alternatively, use **`bouncers`** to pass
  multiple bouncers
- **`middleware`**: either an array of middleware or a function. Works the
  same way as normal express middleware.

### Defining bouncers on subpaths

Use the `secureSubpath` method:

```js
let subpathRouter = router.secureSubpath({
  path: '/secrets',
  bouncers: [bouncer1, bouncer2],
});
```

Returns a new instance of `SecureRouter`.

- **`path`**: appended to the path of the current router
- **`bouncers`**: list of bouncers. Alternatively, use **`bouncer`** to pass
  only one bouncer
- **`bouncer`**: individual bouncer. Alternatively, use **`bouncers`** to pass
  multiple bouncers

### Defining flat bouncers

These bouncers apply to all routes used by the current router. Use the
`bouncer` method:

```
router.bouncer(bouncer);
```

## Contributing

```
npm install
npm run test
```
