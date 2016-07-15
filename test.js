/* eslint-env goodeggs/server-side-test */
import 'goodeggs-ops-api-test-helpers/server';

import Promise from 'bluebird';
import _ from 'lodash';
import express from 'express';
import namespacedRequest from 'namespaced-request';

import Router from './router';

describe('require opt-in middleware with no endpoints explicitly allowing', function () {
  withRunningServer(function () {
    const router = new Router();
    router.use(router.getRequireOptInMiddleware());
    router.get('/foo', function (req, res) {
      res.send('you should never get here!');
    });

    const app = express();
    app.use(router);
    return app;
  });

  it('disables a request to the specifed endpoint', function () {
    return this.request.getPromised('/foo')
    .then(function (response) {
      expect(response.statusCode).to.equal(405);
    });
  });

  it('disables other requests', function () {
    return this.request.getPromised('/bar')
    .then(function (response) {
      expect(response.statusCode).to.equal(405);
    });
  });
});

describe('require opt-in middleware with a subpath explicitly allowing', function () {
  withRunningServer(function () {
    const router = new Router();
    router.use(router.getRequireOptInMiddleware());

    router.withSecurity('/foo', _.constant('ALLOW'))
    .get('/', function (req, res) {
      res.send('you should be allowed here');
    });

    const app = express();
    app.use(router);
    return app;
  });

  it('enables requests inside that path', function () {
    return this.request.getPromised('/foo')
    .then(function (response) {
      expect(response.statusCode).to.equal(200);
    });
  });

  it('disables other requests', function () {
    return this.request.getPromised('/bar')
    .then(function (response) {
      expect(response.statusCode).to.equal(405);
    });
  });
});

describe('require opt-in middleware with an endpoint explicitly allowing and another explicitly denying', function () {
  withRunningServer(function () {
    const router = new Router();
    router.use(router.getRequireOptInMiddleware());

    router.withSecurity('/foo', _.constant('ALLOW'), _.constant('DENY'))
    .get('/', function (req, res) {
      res.send('go away!');
    });

    const app = express();
    app.use(router);
    return app;
  });

  it('disables this specific request', function () {
    return this.request.getPromised('/foo')
    .then(function (response) {
      expect(response.statusCode).to.equal(405);
    });
  });

  it('disables other requests', function () {
    return this.request.getPromised('/bar')
    .then(function (response) {
      expect(response.statusCode).to.equal(405);
    });
  });
});

describe('an embedded router that explicitly allows', function () {
  withRunningServer(function () {
    const router = new Router();
    router.use(router.getRequireOptInMiddleware());

    const embeddedRouter = new Router();
    embeddedRouter.withSecurity('/bar', _.constant('ALLOW'))
    .get('/', function (req, res) {
      res.send('go away!');
    });

    router.use('/foo', embeddedRouter);

    const app = express();
    app.use(router);
    return app;
  });

  it('allows this specific request', function () {
    return this.request.getPromised('/foo/bar')
    .then(function (response) {
      expect(response.statusCode).to.equal(200);
    });
  });

  it('disables other requests', function () {
    return this.request.getPromised('/bar')
    .then(function (response) {
      expect(response.statusCode).to.equal(405);
    });
  });
});

describe('an embedded router that explicitly allows, but the outer router explicitly denies', function () {
  withRunningServer(function () {
    const router = new Router();
    router.use(router.getRequireOptInMiddleware());

    const embeddedRouter = new Router();
    embeddedRouter.withSecurity('/bar', _.constant('ALLOW'))
    .get('/', function (req, res) {
      res.send('go away!');
    });

    router.withSecurity('/foo', _.constant('DENY'))
    .use('/foo', embeddedRouter);

    const app = express();
    app.use(router);
    return app;
  });

  it('allows this specific request', function () {
    return this.request.getPromised('/foo/bar')
    .then(function (response) {
      expect(response.statusCode).to.equal(405);
    });
  });

  it('disables other requests', function () {
    return this.request.getPromised('/bar')
    .then(function (response) {
      expect(response.statusCode).to.equal(405);
    });
  });
});

describe('an embedded router with a parameterized route that explicitly allows', function () {
  withRunningServer(function () {
    const router = new Router();
    router.use(router.getRequireOptInMiddleware());

    const embeddedRouter = new Router();
    embeddedRouter.withSecurity('/info', _.constant('ALLOW'))
    .get('/', function (req, res) {
      res.send('user information');
    });
    router.use('/user/:id', embeddedRouter);

    const app = express();
    app.use(router);
    return app;
  });

  it('allows requests with variable-length ids', function () {
    return this.request.getPromised('/user/19839280981/info')
    .then(function (response) {
      expect(response.statusCode).to.equal(200);
    });
  });

  it('disables other requests', function () {
    return this.request.getPromised('/bar')
    .then(function (response) {
      expect(response.statusCode).to.equal(405);
    });
  });
});

function withRunningServer (appCreator) {
  beforeEach('start server', function (done) {
    if (_.isNil(this.port)) this.port = 19288;
    this.app = appCreator();

    this.request = namespacedRequest(`http://localhost:${this.port}`);
    Promise.promisifyAll(this.request, {suffix: 'Promised'});

    this.server = this.app.listen(this.port, done);
  });

  afterEach('stop server', function (done) {
    if (this.server) return this.server.close(done);
    return process.nextTick(done);
  });
}
