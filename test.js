/* eslint-env goodeggs/server-side-test */
import Promise from 'bluebird';
import _ from 'lodash';
import assert from 'assert';
import express from 'express';
import request from 'request';

import Router from './src/index';

describe('default behavior', function () {
  it('denies requests to endpoints with no security middleware', function () {
    const router = buildRouter();
    router.get('/foo', (req, res) => res.send('you should never get here!'));
    return withRunningServer(router)
    .then(() => expectRequest('GET', '/foo').toReturnCode(401));
  });

  it('denies requests to undefined endpoints', function () {
    return withRunningServer(buildRouter())
    .then(() => expectRequest('GET', '/foo').toReturnCode(401));
  });
});

describe('use()', function () {
  it('allows nesting of secure routers with use()', function () {
    const router = buildRouter();
    const subRouter = new Router();
    subRouter.secureEndpoint({
      method: 'GET',
      path: '/foo',
      bouncers: [
        _.constant(Router.AUTHENTICATE),
        _.constant(Router.AUTHORIZE),
      ],
      middleware: (req, res) => res.sendStatus(200),
    });
    router.use(subRouter);
    return withRunningServer(router)
    .then(() => expectRequest('GET', '/foo').toReturnCode(200));
  });
});

describe('secureEndpoint()', function () {
  it('allows GET access to specific secure endpoints', function () {
    const router = buildRouter();
    router.secureEndpoint({
      method: 'GET',
      path: '/foo',
      bouncers: [
        _.constant(Router.AUTHENTICATE),
        _.constant(Router.AUTHORIZE),
      ],
      middleware: (req, res) => res.sendStatus(200),
    });
    return withRunningServer(router)
    .then(() => expectRequest('GET', '/foo').toReturnCode(200))
    .then(() => expectRequest('POST', '/foo').toReturnCode(401))
    .then(() => expectRequest('GET', '/bar').toReturnCode(401));
  });

  it('allows POST access to specific secure endpoints', function () {
    const router = buildRouter();
    router.secureEndpoint({
      method: 'POST',
      path: '/foo',
      bouncers: [
        _.constant(Router.AUTHENTICATE),
        _.constant(Router.AUTHORIZE),
      ],
      middleware: (req, res) => res.sendStatus(200),
    });
    return withRunningServer(router)
    .then(() => expectRequest('POST', '/foo').toReturnCode(200))
    .then(() => expectRequest('GET', '/foo').toReturnCode(401))
    .then(() => expectRequest('POST', '/bar').toReturnCode(401));
  });

  it('allows PUT access to specific secure endpoints', function () {
    const router = buildRouter();
    router.secureEndpoint({
      method: 'PUT',
      path: '/foo',
      bouncers: [
        _.constant(Router.AUTHENTICATE),
        _.constant(Router.AUTHORIZE),
      ],
      middleware: (req, res) => res.sendStatus(200),
    });
    return withRunningServer(router)
    .then(() => expectRequest('PUT', '/foo').toReturnCode(200))
    .then(() => expectRequest('GET', '/foo').toReturnCode(401))
    .then(() => expectRequest('PUT', '/bar').toReturnCode(401));
  });

  it('allows DELETE access to specific secure endpoints', function () {
    const router = buildRouter();
    router.secureEndpoint({
      method: 'DELETE',
      path: '/foo',
      bouncers: [
        _.constant(Router.AUTHENTICATE),
        _.constant(Router.AUTHORIZE),
      ],
      middleware: (req, res) => res.sendStatus(200),
    });
    return withRunningServer(router)
    .then(() => expectRequest('DELETE', '/foo').toReturnCode(200))
    .then(() => expectRequest('GET', '/foo').toReturnCode(401))
    .then(() => expectRequest('DELETE', '/bar').toReturnCode(401));
  });

  it('allows HEAD access to specific secure endpoints', function () {
    const router = buildRouter();
    router.secureEndpoint({
      method: 'HEAD',
      path: '/foo',
      bouncers: [
        _.constant(Router.AUTHENTICATE),
        _.constant(Router.AUTHORIZE),
      ],
      middleware: (req, res) => res.sendStatus(200),
    });
    return withRunningServer(router)
    .then(() => expectRequest('HEAD', '/foo').toReturnCode(200))
    .then(() => expectRequest('GET', '/foo').toReturnCode(401))
    .then(() => expectRequest('HEAD', '/bar').toReturnCode(401));
  });

  it('allows requests with URL parameters', function () {
    const router = buildRouter();
    router.secureEndpoint({
      method: 'GET',
      path: '/foo',
      bouncers: [
        _.constant(Router.AUTHENTICATE),
        _.constant(Router.AUTHORIZE),
      ],
      middleware: (req, res) => res.sendStatus(200),
    });
    return withRunningServer(router)
    .then(() => expectRequest('GET', '/foo?bar=baz').toReturnCode(200));
  });

  it('ignores bouncers on other paths that do not share a secureSubpath', function () {
    const router = buildRouter();
    const fooRouter = new Router();

    router.use('/foo', fooRouter);
    fooRouter.secureEndpoint({
      method: 'POST',
      path: '/',
      bouncers: [
        _.constant(Router.AUTHENTICATE),
        _.constant(Router.AUTHORIZE),
      ],
      middleware: (req, res) => res.sendStatus(200),
    });
    fooRouter.secureEndpoint({
      method: 'POST',
      path: '/:id',
      bouncers: [
        _.constant(Router.AUTHENTICATE),
        _.constant(Router.denyWith({statusCode: 403})),
      ],
      middleware: (req, res) => res.sendStatus(200),
    });

    return withRunningServer(router)
      .then(() => expectRequest('POST', '/foo').toReturnCode(200))
      .then(() => expectRequest('POST', '/foo/123').toReturnCode(403));
  });
});

describe('secureSubpath()', function () {
  it('allows access to sub-resources', function () {
    const router = buildRouter();
    router.secureSubpath({
      path: '/sub',
      bouncers: [
        _.constant(Router.AUTHENTICATE),
        _.constant(Router.AUTHORIZE),
      ],
    })
    .get('/foo', (req, res) => res.sendStatus(200));
    return withRunningServer(router)
    .then(() => expectRequest('GET', '/sub/foo').toReturnCode(200))
    .then(() => expectRequest('GET', '/sub/bar').toReturnCode(404))
    .then(() => expectRequest('GET', '/bar').toReturnCode(401));
  });

  it('allows access to sub-sub-resources when the security is defined at the upper layer', function () {
    const router = buildRouter();
    const subSubRouter = new Router();
    subSubRouter.get('/foo', (req, res) => res.sendStatus(200));
    router.secureSubpath({
      path: '/sub',
      bouncers: [
        _.constant(Router.AUTHENTICATE),
        _.constant(Router.AUTHORIZE),
      ],
    })
    .use('/subsub', subSubRouter);
    return withRunningServer(router)
    .then(() => expectRequest('GET', '/sub/subsub/foo').toReturnCode(200))
    .then(() => expectRequest('GET', '/sub/foo').toReturnCode(404));
  });

  it('allows access to sub-sub-resources when the security is defined at the lower layer', function () {
    const router = buildRouter();
    const subRouter = new Router();
    subRouter.secureSubpath({
      path: '/subsub',
      bouncers: [
        _.constant(Router.AUTHENTICATE),
        _.constant(Router.AUTHORIZE),
      ],
    })
    .get('/foo', (req, res) => res.sendStatus(200));
    router.use('/sub', subRouter);
    return withRunningServer(router)
    .then(() => expectRequest('GET', '/sub/subsub/foo').toReturnCode(200))
    .then(() => expectRequest('GET', '/sub/foo').toReturnCode(401));
  });
});

describe('bouncer()', function () {
  it('allows you to arbitrarily add bouncers to routers', function () {
    const router = buildRouter();
    router.bouncer(_.constant(Router.AUTHENTICATE));
    router.bouncer(_.constant(Router.AUTHORIZE));
    router.get('/foo', (req, res) => res.sendStatus(200));
    return withRunningServer(router)
    .then(() => expectRequest('GET', '/foo').toReturnCode(200));
  });
});

describe('allowing and denying', function () {
  it('does not allow access to a resource if no security middleware explicitly allows', function () {
    const router = buildRouter();
    router.secureEndpoint({
      method: 'GET',
      path: '/foo',
      bouncers: [
        _.constant(),
        _.constant(),
      ],
      middleware: (req, res) => res.sendStatus(200),
    });
    return withRunningServer(router)
    .then(() => expectRequest('GET', '/foo').toReturnCode(401));
  });

  it('does not allow access to a resource if some security middleware authenticates, some authorizes, and one denies', function () {
    const router = buildRouter();
    router.secureEndpoint({
      method: 'GET',
      path: '/foo',
      bouncers: [
        _.constant(Router.AUTHENTICATE),
        _.constant(Router.AUTHORIZE),
        _.constant(Router.DENY),
      ],
      middleware: (req, res) => res.sendStatus(200),
    });
    return withRunningServer(router)
    .then(() => expectRequest('GET', '/foo').toReturnCode(401));
  });

  it('does allow access to a resource if some security middleware authenticates, some authorizes, and none denies', function () {
    const router = buildRouter();
    router.secureEndpoint({
      method: 'GET',
      path: '/foo',
      bouncers: [
        _.constant(Router.AUTHENTICATE),
        _.constant(Router.AUTHORIZE),
        _.constant(),
      ],
      middleware: (req, res) => res.sendStatus(200),
    });
    return withRunningServer(router)
    .then(() => expectRequest('GET', '/foo').toReturnCode(200));
  });

  it('does not allow access to a resource if the middleware does not authenticate (even if it authorizes)', function () {
    const router = buildRouter();
    router.secureEndpoint({
      method: 'GET',
      path: '/foo',
      bouncers: [
        _.constant(),
        _.constant(Router.AUTHORIZE),
      ],
      middleware: (req, res) => res.sendStatus(200),
    });
    return withRunningServer(router)
    .then(() => expectRequest('GET', '/foo').toReturnCode(401));
  });

  it('does not allow access to a resource (returns a 403) if the middleware authenticates but does not authorize', function () {
    const router = buildRouter();
    router.secureEndpoint({
      method: 'GET',
      path: '/foo',
      bouncers: [
        _.constant(Router.AUTHENTICATE),
        _.constant(),
      ],
      middleware: (req, res) => res.sendStatus(200),
    });
    return withRunningServer(router)
    .then(() => expectRequest('GET', '/foo').toReturnCode(403));
  });
});

describe('bouncer arguments', function () {
  it('provides req object as the first argument to the bouncer function', function () {
    const router = buildRouter();
    let url;
    router.bouncer(function (req) {
      url = req.url;
      return Router.AUTHENTICATE;
    });
    router.bouncer(_.constant(Router.AUTHORIZE));
    return withRunningServer(router)
    .then(() => expectRequest('GET', '/foo').toReturnCode(404))
    .then(function () {
      assert(url.match(/\/foo/));
    });
  });

  it('provides res object as the second argument to the bouncer function', function () {
    const router = buildRouter();
    router.bouncer(function (req, res) {
      res.set('x-foo', 'bar');
      return Router.AUTHENTICATE;
    });
    router.bouncer(_.constant(Router.AUTHORIZE));
    return withRunningServer(router)
    .then(() => expectRequest('GET', '/foo').toHaveHeader('x-foo', 'bar'));
  });
});

describe('custom denials with Router.denyWith()', function () {
  it('can run arbitrary middleware instead of responding', function () {
    const router = buildRouter();
    router.bouncer(function () {
      return Router.denyWith(function (req, res) {
        res.send(408);
      });
    });
    return withRunningServer(router)
    .then(function () {
      return expectRequest('GET', '/foo').toReturnCode(408);
    });
  });

  it('can provide custom status codes', function () {
    const router = buildRouter();
    router.bouncer(function () {
      return Router.denyWith({statusCode: 404});
    });
    return withRunningServer(router)
    .then(() => expectRequest('GET', '/foo').toReturnCode(404));
  });

  it('can provide a custom response payload as a string', function () {
    const router = buildRouter();
    router.bouncer(function () {
      return Router.denyWith({payload: 'Nope, sorry, not today!'});
    });
    return withRunningServer(router)
    .then(function () {
      return Promise.all([
        expectRequest('GET', '/foo').toReturnCode(401),
        expectRequest('GET', '/foo').toReturnBody('Nope, sorry, not today!'),
      ]);
    });
  });

  it('can provide a custom response payload as an object', function () {
    const router = buildRouter();
    router.bouncer(function () {
      return Router.denyWith({payload: {error: true, ms: 10239}});
    });
    return withRunningServer(router)
    .then(function () {
      return Promise.all([
        expectRequest('GET', '/foo').toReturnCode(401),
        expectRequest('GET', '/foo').toReturnBody({error: true, ms: 10239}),
      ]);
    });
  });

  it('applies denials in tree order (root first)', function () {
    /*
     * set up the following structure:
     *    / (bouncer1, bouncer2)
     *      /foo (bouncer3)
     *        /bar (bouncer4)
     */
    const router = buildRouter();
    const subRouter = new Router();
    const middlewareCalls = [];
    router.bouncer(function () {
      return Router.denyWith(function (req, res, next) {
        middlewareCalls.push(1);
        next();
      });
    });
    router.use('/foo', subRouter);
    subRouter.secureEndpoint({
      method: 'GET',
      path: '/bar',
      bouncer () {
        return Router.denyWith(function (req, res) {
          middlewareCalls.push(4);
          res.sendStatus(400);
        });
      },
      middleware: (req, res) => res.send(501),
    });
    router.bouncer(function () {
      return Router.denyWith(function (req, res, next) {
        middlewareCalls.push(2);
        next();
      });
    });
    subRouter.bouncer(function () {
      return Router.denyWith(function (req, res, next) {
        middlewareCalls.push(3);
        next();
      }, 3);
    });
    return withRunningServer(router)
    .then(function () {
      return expectRequest('GET', '/foo/bar').toReturnCode(400)
      .then(function () {
        assert.deepEqual(middlewareCalls, [1, 2, 3, 4]);
      });
    });
  });

  it('returns a 500 for an invalid bouncer (e.g. secure-router@2.1.1. Router.DENY)', function () {
    const router = buildRouter();

    router.bouncer(function () {
      // secure-router@2.1.1 returns this kind of bouncer if you use `Router.denyWith`
      return Promise.resolve({value: 'DENY', statusCode: 401});
    });

    router.secureEndpoint({
      method: 'GET',
      path: '/bar',
      middleware: (req, res) => res.send(200),
    });

    return withRunningServer(router)
    .then(function () {
      return expectRequest('GET', '/bar').toReturnCode(500);
    });
  });
});


function expectRequest (method, path) {
  const reqPromise = Promise.fromCallback(function (cb) {
    request({
      method,
      json: true,
      url: `http://localhost:19288${path}`,
    }, cb);
  });

  return {
    toReturnCode (responseCode) {
      return reqPromise
      .then(function (response) {
        assert.equal(response.statusCode, responseCode, `Expected request to ${path} to return code ${responseCode} but got ${response.statusCode}.`);
      });
    },
    toHaveHeader (name, value) {
      return reqPromise
      .then(function (response) {
        assert.equal(response.headers[name], value, `Expected request to ${path} to respond with header ${name} of value ${value}, but got ${response.headers[name]} instead.`);
      });
    },
    toReturnBody (body) {
      return reqPromise
      .then(function (response) {
        assert.deepEqual(response.body, body, `Expected request to ${path} to return body ${JSON.stringify(body)}, but got ${JSON.stringify(response.body)} instead.`);
      });
    },
  };
}

function buildRouter () {
  const router = new Router();
  router.bounceRequests();
  return router;
}

let sharedServer;
function withRunningServer (router) {
  const app = express();
  app.use(router);
  return Promise.fromCallback(function (done) {
    sharedServer = app.listen(19288, done);
  });
}
afterEach('stop server', function (done) {
  if (sharedServer) {
    return sharedServer.close(function () {
      sharedServer = null;
      done();
    });
  }
  return process.nextTick(done);
});
