import Promise from 'bluebird';
import _ from 'lodash';
import assert from 'assert';
import express, {NextFunction, Response} from 'express';
import {describe, it, afterEach} from 'mocha';
import {Server, IncomingMessage, ServerResponse} from 'http';

import Router, {SecureRouterRequest} from '.';

describe('default behavior', function () {
  it('denies requests to endpoints with no security middleware', async function () {
    const router = buildRouter();
    router.get('/foo', (_req: SecureRouterRequest, res: Response) =>
      res.send('you should never get here!'),
    );
    await withRunningServer(router);
    return expectRequest({method: 'GET', path: '/foo'}).toReturnCode(401);
  });

  it('denies requests to undefined endpoints', async function () {
    await withRunningServer(buildRouter());
    return expectRequest({method: 'GET', path: '/foo'}).toReturnCode(401);
  });
});

describe('use()', function () {
  it('allows nesting of secure routers with use()', async function () {
    const router = buildRouter();
    const subRouter = new Router();
    subRouter.secureEndpoint({
      method: 'GET',
      path: '/foo',
      bouncers: [_.constant(Router.AUTHENTICATE), _.constant(Router.AUTHORIZE)],
      middleware: (_req: SecureRouterRequest, res: Response) => res.sendStatus(200),
    });
    router.use(subRouter);
    await withRunningServer(router);
    return expectRequest({method: 'GET', path: '/foo'}).toReturnCode(200);
  });

  it('provides req.matchedRoutes to middlewares even when 404', async function () {
    const router = buildRouter();
    const subRouter = new Router();
    subRouter.secureSubpath({
      path: '/nested',
      bouncers: [_.constant(Router.AUTHENTICATE), _.constant(Router.AUTHORIZE)],
    });
    router.use('/base/:baseId', subRouter);
    router.use((req: SecureRouterRequest, res: Response) => {
      res.status(404);
      res.json(req.matchedRoutes);
    });
    await withRunningServer(router);
    return expectRequest({method: 'GET', path: '/base/2/nested/239847'}).toReturnBody([
      '/base/:baseId',
      '/nested',
    ]);
  });
});

describe('secureEndpoint()', function () {
  it('allows GET access to specific secure endpoints', async function () {
    const router = buildRouter();
    router.secureEndpoint({
      method: 'GET',
      path: '/foo',
      bouncers: [_.constant(Router.AUTHENTICATE), _.constant(Router.AUTHORIZE)],
      middleware: (_req: SecureRouterRequest, res: Response) => res.sendStatus(200),
    });
    await withRunningServer(router);
    await expectRequest({method: 'GET', path: '/foo'}).toReturnCode(200);
    await expectRequest({method: 'POST', path: '/foo'}).toReturnCode(401);
    return expectRequest({method: 'GET', path: '/bar'}).toReturnCode(401);
  });

  it('allows POST access to specific secure endpoints', async function () {
    const router = buildRouter();
    router.secureEndpoint({
      method: 'POST',
      path: '/foo',
      bouncers: [_.constant(Router.AUTHENTICATE), _.constant(Router.AUTHORIZE)],
      middleware: (_req: SecureRouterRequest, res: Response) => res.sendStatus(200),
    });
    await withRunningServer(router);
    await expectRequest({method: 'POST', path: '/foo'}).toReturnCode(200);
    await expectRequest({method: 'GET', path: '/foo'}).toReturnCode(401);
    return expectRequest({method: 'POST', path: '/bar'}).toReturnCode(401);
  });

  it('allows PUT access to specific secure endpoints', async function () {
    const router = buildRouter();
    router.secureEndpoint({
      method: 'PUT',
      path: '/foo',
      bouncers: [_.constant(Router.AUTHENTICATE), _.constant(Router.AUTHORIZE)],
      middleware: (_req: SecureRouterRequest, res: Response) => res.sendStatus(200),
    });
    await withRunningServer(router);
    await expectRequest({method: 'PUT', path: '/foo'}).toReturnCode(200);
    await expectRequest({method: 'GET', path: '/foo'}).toReturnCode(401);
    return expectRequest({method: 'PUT', path: '/bar'}).toReturnCode(401);
  });

  it('allows DELETE access to specific secure endpoints', async function () {
    const router = buildRouter();
    router.secureEndpoint({
      method: 'DELETE',
      path: '/foo',
      bouncers: [_.constant(Router.AUTHENTICATE), _.constant(Router.AUTHORIZE)],
      middleware: (_req: SecureRouterRequest, res: Response) => res.sendStatus(200),
    });
    await withRunningServer(router);
    await expectRequest({method: 'DELETE', path: '/foo'}).toReturnCode(200);
    await expectRequest({method: 'GET', path: '/foo'}).toReturnCode(401);
    return expectRequest({method: 'DELETE', path: '/bar'}).toReturnCode(401);
  });

  it('allows HEAD access to specific secure endpoints', async function () {
    const router = buildRouter();
    router.secureEndpoint({
      method: 'HEAD',
      path: '/foo',
      bouncers: [_.constant(Router.AUTHENTICATE), _.constant(Router.AUTHORIZE)],
      middleware: (_req: SecureRouterRequest, res: Response) => res.sendStatus(200),
    });
    await withRunningServer(router);
    await expectRequest({method: 'HEAD', path: '/foo'}).toReturnCode(200);
    await expectRequest({method: 'GET', path: '/foo'}).toReturnCode(401);
    return expectRequest({method: 'HEAD', path: '/bar'}).toReturnCode(401);
  });

  it('allows requests with URL parameters', async function () {
    const router = buildRouter();
    router.secureEndpoint({
      method: 'GET',
      path: '/foo',
      bouncers: [_.constant(Router.AUTHENTICATE), _.constant(Router.AUTHORIZE)],
      middleware: (_req: SecureRouterRequest, res: Response) => res.sendStatus(200),
    });
    await withRunningServer(router);
    return expectRequest({method: 'GET', path: '/foo?bar=baz'}).toReturnCode(200);
  });

  it('ignores bouncers on other paths that do not share a secureSubpath', async function () {
    const router = buildRouter();
    const fooRouter = new Router();

    router.use('/foo', fooRouter);
    fooRouter.secureEndpoint({
      method: 'POST',
      path: '/',
      bouncers: [_.constant(Router.AUTHENTICATE), _.constant(Router.AUTHORIZE)],
      middleware: (_req: SecureRouterRequest, res: Response) => res.sendStatus(200),
    });
    fooRouter.secureEndpoint({
      method: 'POST',
      path: '/:id',
      bouncers: [
        _.constant(Router.AUTHENTICATE),
        _.constant(Router.denyWith({params: {statusCode: 403}})),
      ],
      middleware: (_req: SecureRouterRequest, res: Response) => res.sendStatus(200),
    });

    await withRunningServer(router);
    await expectRequest({method: 'POST', path: '/foo'}).toReturnCode(200);
    return expectRequest({method: 'POST', path: '/foo/123'}).toReturnCode(403);
  });

  it('provides req.matchedRoutes to middlewares', async function () {
    const router = buildRouter();
    const subRouter = new Router();
    subRouter.secureEndpoint({
      method: 'GET',
      path: '/nested/:nestedId',
      bouncers: [_.constant(Router.AUTHENTICATE), _.constant(Router.AUTHORIZE)],
      middleware: (req: SecureRouterRequest, res: Response) => {
        res.json(req.matchedRoutes);
        res.sendStatus(200);
      },
    });
    router.use('/base/:baseId', subRouter);
    await withRunningServer(router);
    return expectRequest({method: 'GET', path: '/base/2/nested/239847'}).toReturnBody([
      '/base/:baseId',
      '/nested/:nestedId',
    ]);
  });

  // regression test, see https://github.com/expressjs/express/issues/2879#issuecomment-269433170
  it('req.matchedRoutes is correct when error middlewares run', async function () {
    const router = buildRouter();
    const subRouter = new Router();
    subRouter.secureEndpoint({
      method: 'GET',
      path: '/nested/:nestedId',
      bouncers: [_.constant(Router.AUTHENTICATE), _.constant(Router.AUTHORIZE)],
      middleware: (_req, _res, next) => {
        next(new Error('no.'));
      },
    });
    router.use('/base/:baseId', subRouter);
    router.use((err: Error, _req: SecureRouterRequest, _res: Response, next: NextFunction) => {
      next(err);
    });

    router.use((_err: Error, req: SecureRouterRequest, res: Response, _next: NextFunction) => {
      res.json(req.matchedRoutes);
      res.sendStatus(200);
    });
    await withRunningServer(router);
    return expectRequest({method: 'GET', path: '/base/2/nested/239847'}).toReturnBody([
      '/base/:baseId',
      '/nested/:nestedId',
    ]);
  });
});

describe('secureSubpath()', function () {
  it('allows access to sub-resources', async function () {
    const router = buildRouter();
    router
      .secureSubpath({
        path: '/sub',
        bouncers: [_.constant(Router.AUTHENTICATE), _.constant(Router.AUTHORIZE)],
      })
      .get('/foo', (_req: SecureRouterRequest, res: Response) => res.sendStatus(200));
    await withRunningServer(router);
    await expectRequest({method: 'GET', path: '/sub/foo'}).toReturnCode(200);
    await expectRequest({method: 'GET', path: '/sub/bar'}).toReturnCode(404);
    return expectRequest({method: 'GET', path: '/bar'}).toReturnCode(401);
  });

  it('allows access to sub-sub-resources when the security is defined at the upper layer', async function () {
    const router = buildRouter();
    const subSubRouter = new Router();
    subSubRouter.get('/foo', (_req: SecureRouterRequest, res: Response) => res.sendStatus(200));
    router
      .secureSubpath({
        path: '/sub',
        bouncers: [_.constant(Router.AUTHENTICATE), _.constant(Router.AUTHORIZE)],
      })
      .use('/subsub', subSubRouter);
    await withRunningServer(router);
    await expectRequest({method: 'GET', path: '/sub/subsub/foo'}).toReturnCode(200);
    return expectRequest({method: 'GET', path: '/sub/foo'}).toReturnCode(404);
  });

  it('allows access to sub-sub-resources when the security is defined at the lower layer', async function () {
    const router = buildRouter();
    const subRouter = new Router();
    subRouter
      .secureSubpath({
        path: '/subsub',
        bouncers: [_.constant(Router.AUTHENTICATE), _.constant(Router.AUTHORIZE)],
      })
      .get('/foo', (_req: SecureRouterRequest, res: Response) => res.sendStatus(200));
    router.use('/sub', subRouter);
    await withRunningServer(router);
    await expectRequest({method: 'GET', path: '/sub/subsub/foo'}).toReturnCode(200);
    return expectRequest({method: 'GET', path: '/sub/foo'}).toReturnCode(401);
  });

  it('provides req.matchedRoutes to middlewares', async function () {
    const router = buildRouter();
    const subRouter = new Router();
    subRouter
      .secureSubpath({
        path: '/nested',
        bouncers: [_.constant(Router.AUTHENTICATE), _.constant(Router.AUTHORIZE)],
      })
      .get('/:nestedId', (req: SecureRouterRequest, res: Response) => {
        res.json(req.matchedRoutes);
        res.sendStatus(200);
      });
    router.use('/base/:baseId', subRouter);
    await withRunningServer(router);
    return expectRequest({method: 'GET', path: '/base/2/nested/239847'}).toReturnBody([
      '/base/:baseId',
      '/nested',
      '/:nestedId',
    ]);
  });

  // regression test, see https://github.com/expressjs/express/issues/2879#issuecomment-269433170
  it('req.matchedRoutes is correct when error middlewares run', async function () {
    const router = buildRouter();
    const subRouter = new Router();
    subRouter
      .secureSubpath({
        path: '/nested',
        bouncers: [_.constant(Router.AUTHENTICATE), _.constant(Router.AUTHORIZE)],
      })
      .get('/:nestedId', (_req: SecureRouterRequest, _res: Response, next: NextFunction) => {
        next(new Error('no.'));
      });
    router.use('/base/:baseId', subRouter);
    router.use((err, _req, _res, next) => {
      next(err);
    });

    router.use((_err: Error, req: SecureRouterRequest, res: Response, _next: NextFunction) => {
      res.json(req.matchedRoutes);
      res.sendStatus(200);
    });
    await withRunningServer(router);
    return expectRequest({method: 'GET', path: '/base/2/nested/239847'}).toReturnBody([
      '/base/:baseId',
      '/nested',
      '/:nestedId',
    ]);
  });

  it('req.matchedRoutes never includes a trailing slash', async function () {
    const router = buildRouter();
    const subRouter = new Router();
    subRouter
      .secureSubpath({
        path: '/foo',
        bouncers: [_.constant(Router.AUTHENTICATE), _.constant(Router.AUTHORIZE)],
      })
      .get('/', (_req: SecureRouterRequest, _res: Response, next: NextFunction) => {
        next(new Error('no.'));
      });
    subRouter
      .secureSubpath({
        path: '/',
        bouncers: [_.constant(Router.AUTHENTICATE), _.constant(Router.AUTHORIZE)],
      })
      .get('/bar', (_req: SecureRouterRequest, _res: Response, next: NextFunction) => {
        next(new Error('no.'));
      });
    router.use('/base', subRouter);
    router.use((err: Error, _req: SecureRouterRequest, _res: Response, next: NextFunction) => {
      next(err);
    });

    router.use((_err: Error, req: SecureRouterRequest, res: Response, _next: NextFunction) => {
      res.json(req.matchedRoutes);
      res.sendStatus(200);
    });
    await withRunningServer(router);
    return Promise.all([
      expectRequest({method: 'GET', path: '/base/foo'}).toReturnBody(['/base', '/foo']),
      expectRequest({method: 'GET', path: '/base/foo/'}).toReturnBody(['/base', '/foo']),
      expectRequest({method: 'GET', path: '/base/bar'}).toReturnBody(['/base', '/bar']),
      expectRequest({method: 'GET', path: '/base/bar/'}).toReturnBody(['/base', '/bar']),
    ]);
  });
});

describe('bouncer()', function () {
  it('allows you to arbitrarily add bouncers to routers', async function () {
    const router = buildRouter();
    router.bouncer({bouncer: _.constant(Router.AUTHENTICATE)});
    router.bouncer({bouncer: _.constant(Router.AUTHORIZE)});
    router.get('/foo', (_req: SecureRouterRequest, res: Response) => res.sendStatus(200));
    await withRunningServer(router);
    return expectRequest({method: 'GET', path: '/foo'}).toReturnCode(200);
  });
});

describe('allowing and denying', function () {
  it('does not allow access to a resource if no security middleware explicitly allows', async function () {
    const router = buildRouter();
    router.secureEndpoint({
      method: 'GET',
      path: '/foo',
      bouncers: [_.constant(undefined), _.constant(undefined)],
      middleware: (_req: SecureRouterRequest, res: Response) => res.sendStatus(200),
    });
    await withRunningServer(router);
    return expectRequest({method: 'GET', path: '/foo'}).toReturnCode(401);
  });

  it('does not allow access to a resource if some security middleware authenticates, some authorizes, and one denies', async function () {
    const router = buildRouter();
    router.secureEndpoint({
      method: 'GET',
      path: '/foo',
      bouncers: [
        _.constant(Router.AUTHENTICATE),
        _.constant(Router.AUTHORIZE),
        _.constant(Router.DENY),
      ],
      middleware: (_req: SecureRouterRequest, res: Response) => res.sendStatus(200),
    });
    await withRunningServer(router);
    return expectRequest({method: 'GET', path: '/foo'}).toReturnCode(401);
  });

  it('does allow access to a resource if some security middleware authenticates, some authorizes, and none denies', async function () {
    const router = buildRouter();
    router.secureEndpoint({
      method: 'GET',
      path: '/foo',
      bouncers: [
        _.constant(Router.AUTHENTICATE),
        _.constant(Router.AUTHORIZE),
        _.constant(undefined),
      ],
      middleware: (_req: SecureRouterRequest, res: Response) => res.sendStatus(200),
    });
    await withRunningServer(router);
    return expectRequest({method: 'GET', path: '/foo'}).toReturnCode(200);
  });

  it('does not allow access to a resource if the middleware does not authenticate (even if it authorizes)', async function () {
    const router = buildRouter();
    router.secureEndpoint({
      method: 'GET',
      path: '/foo',
      bouncers: [_.constant(undefined), _.constant(Router.AUTHORIZE)],
      middleware: (_req: SecureRouterRequest, res: Response) => res.sendStatus(200),
    });
    await withRunningServer(router);
    return expectRequest({method: 'GET', path: '/foo'}).toReturnCode(401);
  });

  it('does not allow access to a resource (returns a 403) if the middleware authenticates but does not authorize', async function () {
    const router = buildRouter();
    router.secureEndpoint({
      method: 'GET',
      path: '/foo',
      bouncers: [_.constant(Router.AUTHENTICATE), _.constant(undefined)],
      middleware: (_req: SecureRouterRequest, res: Response) => res.sendStatus(200),
    });
    await withRunningServer(router);
    return expectRequest({method: 'GET', path: '/foo'}).toReturnCode(403);
  });
});

describe('bouncer arguments', function () {
  it('provides req object as the first argument to the bouncer function', async function () {
    const router = buildRouter();
    let url = '';
    router.bouncer({
      bouncer(req: SecureRouterRequest) {
        url = req.url;
        return Router.AUTHENTICATE;
      },
    });
    router.bouncer({bouncer: _.constant(Router.AUTHORIZE)});
    await withRunningServer(router);
    await expectRequest({method: 'GET', path: '/foo'}).toReturnCode(404);
    assert(url.match(/\/foo/));
  });

  it('provides res object as the second argument to the bouncer function', async function () {
    const router = buildRouter();
    router.bouncer({
      bouncer(_req: SecureRouterRequest, res: Response) {
        res.set('x-foo', 'bar');
        return Router.AUTHENTICATE;
      },
    });
    router.bouncer({bouncer: _.constant(Router.AUTHORIZE)});
    await withRunningServer(router);
    return expectRequest({method: 'GET', path: '/foo'}).toHaveHeader('x-foo', 'bar');
  });
});

describe('custom denials with Router.denyWith()', function () {
  it('can run arbitrary middleware instead of responding', async function () {
    const router = buildRouter();
    router.bouncer({
      bouncer() {
        return Router.denyWith({
          params(_req: SecureRouterRequest, res: Response) {
            res.send(408);
          },
        });
      },
    });
    await withRunningServer(router);
    return expectRequest({method: 'GET', path: '/foo'}).toReturnCode(408);
  });

  it('can provide custom status codes', async function () {
    const router = buildRouter();
    router.bouncer({
      bouncer() {
        return Router.denyWith({params: {statusCode: 404}});
      },
    });
    await withRunningServer(router);
    return expectRequest({method: 'GET', path: '/foo'}).toReturnCode(404);
  });

  it('can provide a custom response payload as a string', async function () {
    const router = buildRouter();
    router.bouncer({
      bouncer() {
        return Router.denyWith({params: {payload: 'Nope, sorry, not today!'}});
      },
    });
    await withRunningServer(router);
    return Promise.all([
      expectRequest({method: 'GET', path: '/foo'}).toReturnCode(401),
      expectRequest({method: 'GET', path: '/foo'}).toReturnBody('Nope, sorry, not today!'),
    ]);
  });

  it('can provide a custom response payload as an object', async function () {
    const router = buildRouter();
    router.bouncer({
      bouncer() {
        return Router.denyWith({params: {payload: {error: true, ms: 10239}}});
      },
    });
    await withRunningServer(router);
    return Promise.all([
      expectRequest({method: 'GET', path: '/foo'}).toReturnCode(401),
      expectRequest({method: 'GET', path: '/foo'}).toReturnBody({error: true, ms: 10239}),
    ]);
  });

  it('applies denials in tree order (root first)', async function () {
    /*
     * set up the following structure:
     *    / (bouncer1, bouncer2)
     *      /foo (bouncer3)
     *        /bar (bouncer4)
     */
    const router = buildRouter();
    const subRouter = new Router();
    const middlewareCalls: number[] = [];
    router.bouncer({
      bouncer() {
        return Router.denyWith({
          params(_req: SecureRouterRequest, _res: Response, next: NextFunction) {
            middlewareCalls.push(1);
            next();
          },
        });
      },
    });
    router.use('/foo', subRouter);
    subRouter.secureEndpoint({
      method: 'GET',
      path: '/bar',
      bouncer() {
        return Router.denyWith({
          params(_req: SecureRouterRequest, res: Response) {
            middlewareCalls.push(4);
            res.sendStatus(400);
          },
        });
      },
      middleware: (_req: SecureRouterRequest, res: Response) => res.send(501),
    });
    router.bouncer({
      bouncer() {
        return Router.denyWith({
          params(_req: SecureRouterRequest, _res, next) {
            middlewareCalls.push(2);
            next();
          },
        });
      },
    });
    subRouter.bouncer({
      bouncer() {
        return Router.denyWith({
          params(_req: SecureRouterRequest, _res, next) {
            middlewareCalls.push(3);
            next();
          },
          i: 3,
        });
      },
    });
    await withRunningServer(router);
    expectRequest({method: 'GET', path: '/foo/bar'}).toReturnCode(400);
    assert.deepEqual(middlewareCalls, [1, 2, 3, 4]);
  });

  it('returns a 500 for an invalid bouncer (e.g. secure-router@2.1.1. Router.DENY)', async function () {
    const router = buildRouter();

    router.bouncer({
      bouncer() {
        return Promise.resolve({value: 'DENY', statusCode: 401});
      },
    });

    router.secureEndpoint({
      method: 'GET',
      path: '/bar',
      middleware: (_req: SecureRouterRequest, res: Response) => res.send(200),
    });

    await withRunningServer(router);
    return expectRequest({method: 'GET', path: '/bar'}).toReturnCode(500);
  });
});

function expectRequest({method, path}: {method: string; path: string}): {
  toReturnCode(responseCode: number): globalThis.Promise<void>;
  toHaveHeader(name: string, value: string): globalThis.Promise<void>;
  toReturnBody(body: string[] | {error: boolean; ms: number} | string): globalThis.Promise<void>;
} {
  const reqPromise = Promise.fromCallback(function (cb) {
    request(
      {
        method,
        json: true,
        url: `http://localhost:19288${path}`,
      },
      cb,
    );
  });

  return {
    async toReturnCode(responseCode: number): globalThis.Promise<void> {
      const response = await reqPromise;
      assert.equal(
        response.statusCode,
        responseCode,
        `Expected request to ${path} to return code ${responseCode} but got ${response.statusCode}.`,
      );
    },
    async toHaveHeader(name: string, value: string): globalThis.Promise<void> {
      const response = await reqPromise;
      assert.equal(
        response.headers[name],
        value,
        `Expected request to ${path} to respond with header ${name} of value ${value}, but got ${response.headers[name]} instead.`,
      );
    },
    async toReturnBody(
      body: string[] | {error: boolean; ms: number} | string,
    ): globalThis.Promise<void> {
      const response = await reqPromise;
      assert.deepEqual(
        response.body,
        body,
        `Expected request to ${path} to return body ${JSON.stringify(
          body,
        )}, but got ${JSON.stringify(response.body)} instead.`,
      );
    },
  };
}

function buildRouter(): Router {
  const router = new Router();
  router.bounceRequests();
  return router;
}

let sharedServer: Server<typeof IncomingMessage, typeof ServerResponse> | null;
function withRunningServer(router: Router): Promise<unknown> {
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
  process.nextTick(done);
});
