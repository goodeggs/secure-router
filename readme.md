# Secure Router

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
    ((req) => if (req.user) return 'AUTHENTICATE'),
    ((req) => if (req.user.isRoyalty) return 'AUTHORIZE'),
  ],
  middleware (req, res) {
    req.send(theCrownJewels)
  },
});

/* OR */

secretRouter = router.secureSubpath({
  path: '/secrets',
  bouncers: [
    ((req) => if (req.user) return 'AUTHENTICATE'),
    ((req) => if (req.user.classification === 'MI6') return 'AUTHORIZE'),
    ((req) => if (req.user.number === '006') return 'DENY'),
  ],
});

secretRouter.get('/mission-briefs', (req, res) => res.send(nextMission));
```

[rfc401]: https://httpstatuses.com/401
[rfc403]: https://httpstatuses.com/403
[express]: https://expressjs.com/

## The rules:

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

## Contributing

```
npm install
npm run test
```
