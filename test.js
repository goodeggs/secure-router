/* eslint-env goodeggs/server-side-test */
import 'goodeggs-ops-api-test-helpers/server';

import Promise from 'bluebird';
import _ from 'lodash';
import assert from 'assert';
import express from 'express';
import request from 'request';

import Router from './index';

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

describe('secureEndpoint', function () {
  it('allows GET access to specific secure endpoints', function () {
    const router = buildRouter();
    router.secureEndpoint({
      method: 'GET',
      path: '/foo',
      bouncers: [
        _.constant('AUTHENTICATE'),
        _.constant('AUTHORIZE'),
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
        _.constant('AUTHENTICATE'),
        _.constant('AUTHORIZE'),
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
        _.constant('AUTHENTICATE'),
        _.constant('AUTHORIZE'),
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
        _.constant('AUTHENTICATE'),
        _.constant('AUTHORIZE'),
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
        _.constant('AUTHENTICATE'),
        _.constant('AUTHORIZE'),
      ],
      middleware: (req, res) => res.sendStatus(200),
    });
    return withRunningServer(router)
    .then(() => expectRequest('HEAD', '/foo').toReturnCode(200))
    .then(() => expectRequest('GET', '/foo').toReturnCode(401))
    .then(() => expectRequest('HEAD', '/bar').toReturnCode(401));
  });
});

describe('secureSubpath', function () {
  it('allows access to sub-resources', function () {
    const router = buildRouter();
    router.secureSubpath({
      path: '/sub',
      bouncers: [
        _.constant('AUTHENTICATE'),
        _.constant('AUTHORIZE'),
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
        _.constant('AUTHENTICATE'),
        _.constant('AUTHORIZE'),
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
        _.constant('AUTHENTICATE'),
        _.constant('AUTHORIZE'),
      ],
    })
    .get('/foo', (req, res) => res.sendStatus(200));
    router.use('/sub', subRouter);
    return withRunningServer(router)
    .then(() => expectRequest('GET', '/sub/subsub/foo').toReturnCode(200))
    .then(() => expectRequest('GET', '/sub/foo').toReturnCode(401));
  });
});

describe('bouncer', function () {
  it('allows you to arbitrarily add bouncers to routers', function () {
    const router = buildRouter();
    router.bouncer(_.constant('AUTHENTICATE'));
    router.bouncer(_.constant('AUTHORIZE'));
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
        _.constant('AUTHENTICATE'),
        _.constant('AUTHORIZE'),
        _.constant('DENY'),
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
        _.constant('AUTHENTICATE'),
        _.constant('AUTHORIZE'),
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
        _.constant('AUTHORIZE'),
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
        _.constant('AUTHENTICATE'),
        _.constant(),
      ],
      middleware: (req, res) => res.sendStatus(200),
    });
    return withRunningServer(router)
    .then(() => expectRequest('GET', '/foo').toReturnCode(403));
  });
});

function expectRequest (method, path) {
  return {
    toReturnCode (responseCode) {
      return Promise.fromCallback(function (cb) {
        request({
          method,
          url: `http://localhost:19288${path}`,
        }, cb);
      })
      .then(function (response) {
        assert.equal(response.statusCode, responseCode, `Expected request to ${path} to return code ${responseCode} but got ${response.statusCode}.`);
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
