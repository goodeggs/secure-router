import BaseRouter, {RouterMethod, ErrorHandleFunction, Path} from 'router';
import Promise from 'bluebird';
import _ from 'lodash';
import configureDebug from 'debug';
import http from 'http';
import pathToRegexp, {PathRegExp} from 'path-to-regexp';
import url from 'url';
import async from 'async';
import {Request, RequestHandler, Response} from 'express';

const debug = configureDebug('secure-router');

const AUTHORIZE = 'AUTHORIZE';
const AUTHENTICATE = 'AUTHENTICATE';
const DENY = 'DENY';

export type AccessStatus =
  | typeof Router.AUTHORIZE
  | typeof Router.AUTHENTICATE
  | typeof Router.DENY;

export interface SecureRouterRequestHandler extends RequestHandler {
  __mountpath?: string;
}

export interface SecureRouterRequest extends Request {
  matchedRoutes?: string[];
  __route?: string;
}

const parseError = (error: unknown): Error => {
  if (error instanceof Error) return error;
  return new Error(String(error));
};

class Router extends BaseRouter {
  pathDefinitions: Array<
    NonNullable<
      {
        regexp: PathRegExp;
        innerRouters: Router[];
        bouncers: Array<
          | ((req: SecureRouterRequest, res: Response) => AccessStatus | Promise<AccessStatus>)
          | ((req: SecureRouterRequest) => AccessStatus | Promise<AccessStatus>)
        >;
        methods: string[];
      } & {
        path: string;
        innerRouters: Router[];
        bouncers?: Array<
          | ((req: SecureRouterRequest, res: Response) => AccessStatus | Promise<AccessStatus>)
          | ((req: SecureRouterRequest) => AccessStatus | Promise<AccessStatus>)
        >;
        methods?: string[];
      }
    >
  >;
  bouncers: Array<
    | ((req: SecureRouterRequest, res: Response) => AccessStatus | Promise<AccessStatus>)
    | ((req: SecureRouterRequest) => AccessStatus | Promise<AccessStatus>)
  >;
  stack: SecureRouterRequestHandler[] = [];
  /* eslint-disable @typescript-eslint/naming-convention */
  static DENY: {value: string; middleware: (req: SecureRouterRequest, res: Response) => void};
  static AUTHORIZE: {value: string};
  static AUTHENTICATE: {value: string};
  /* eslint-enable @typescript-eslint/naming-convention */

  constructor(...args: undefined[]) {
    super(...args);
    this.bouncers = [];
    this.pathDefinitions = [];
  }

  static denyWith({
    params,
    i,
  }: {
    params:
      | {
          statusCode?: number;
          payload?: string | {error: true; ms: number};
        }
      | RequestHandler;
    i?: number;
  }): typeof Router.DENY {
    if (_.isFunction(params)) {
      debug('Creating denial with a provided middleware function');
      const middleware = params;
      return _.assign({}, Router.DENY, {middleware, i});
    } else if (_.isObject(params)) {
      debug('Creating denial with params', params);
      const middleware = (_req: SecureRouterRequest, res: Response): void => {
        debug('Responding to request with procedural denyWith middleware');
        res.status(_.get(params, 'statusCode', 401));
        res.send(params.payload);
      };
      return _.assign({}, Router.DENY, {middleware, i});
    }
    throw new Error(`Params must be an object or a function got: ${typeof params}`);
  }

  bounceRequests(): Router {
    const router = this;
    router.use(function (
      req: SecureRouterRequest,
      res: Response,
      next: async.ErrorCallback<Error>,
    ) {
      const parsedUrl = url.parse(req.url);
      router
        .resolveCustomSecurity(req, res, parsedUrl.pathname as string)
        .then(function (results: {value: string; middleware: any}) {
          function match(result: {value: string}, expectedValue: string): boolean {
            return _.isObject(result) && result.value === expectedValue;
          }

          function someResultsMatch(expectedValue: string): boolean {
            return _.some(results, (result) => match(result, expectedValue));
          }
          function noResultsMatch(expectedValue: string): boolean {
            return _.every(results, (result) => !match(result, expectedValue));
          }

          if (someResultsMatch(DENY)) {
            const denyResults = _.filter(results, (result: {value: string}) => match(result, DENY));
            debug('Got one or more DENY', {denyResults});
            // TODO(@max) sort here???
            async.eachSeries(
              _.map(denyResults, function (result) {
                return result.middleware;
              }),
              function (middleware, callback) {
                try {
                  middleware(req, res, callback);
                } catch (err) {
                  const error = parseError(err);
                  debug('DENY middleware threw a synchronous error', error.stack);
                  callback(error);
                }
              },
              next,
            );
            return;
          }

          if (noResultsMatch(AUTHENTICATE)) {
            debug('Got no AUTHENTICATE from any bouncer, sending 401', {results});
            return res.sendStatus(401);
          }

          if (noResultsMatch(AUTHORIZE)) {
            debug('Got no AUTHORIZE from any bouncer, sending 403', {results});
            return res.sendStatus(403);
          }

          debug('Got one or more AUTHENTICATE and one or more AUTHORIZE', {results});
          next();
        });
    });
    return router;
  }

  secureSubpath(params: {
    path: string;
    bouncer?:
      | ((req: SecureRouterRequest, res: Response) => AccessStatus | Promise<AccessStatus>)
      | ((req: SecureRouterRequest) => AccessStatus | Promise<AccessStatus>);
    bouncers?: Array<
      | ((req: SecureRouterRequest, res: Response) => AccessStatus | Promise<AccessStatus>)
      | ((req: SecureRouterRequest) => AccessStatus | Promise<AccessStatus>)
    >;
  }): Router {
    let {bouncers} = params;
    if (_.isNil(bouncers)) bouncers = [];
    if (_.isFunction(params.bouncer)) bouncers.push(params.bouncer);

    const innerRouter = new Router();
    this.pathDefinitions.push(
      createPathDefinition({
        path: params.path,
        innerRouters: [innerRouter],
        bouncers,
      }),
    );
    this.use(params.path, innerRouter);
    return innerRouter;
  }

  secureEndpoint(params: {
    path: string;
    method: string;
    middleware: RequestHandler | RequestHandler[];
    bouncer?:
      | ((req: SecureRouterRequest, res: Response) => AccessStatus | Promise<AccessStatus>)
      | ((req: SecureRouterRequest) => AccessStatus | Promise<AccessStatus>);
    bouncers?: Array<
      | ((
          req: SecureRouterRequest,
          res: Response,
        ) => AccessStatus | Promise<AccessStatus> | undefined)
      | ((req: SecureRouterRequest) => AccessStatus | Promise<AccessStatus> | undefined)
    >;
  }): Router {
    let {bouncers} = params;
    if (_.isNil(bouncers)) bouncers = [];
    if (_.isFunction(params.bouncer)) bouncers.push(params.bouncer);

    let {middleware} = params;
    if (_.isFunction(middleware)) middleware = [middleware];

    this.pathDefinitions.push(
      createPathDefinition({
        path: params.path,
        bouncers,
        methods: [params.method.toUpperCase()],
      }),
    );

    /* actually mount the route */
    this[params.method.toLowerCase() as RouterMethod](params.path, ...middleware);
    return this;
  }

  use = (path: Path | RequestHandler | ErrorHandleFunction, ...innerRouters: Router[]): void => {
    function isSecureRouter(router: Router): boolean {
      return _.isFunction(router.resolveCustomSecurity);
    }

    const pathIsString = _.isString(path);
    if (pathIsString) {
      let {pathDefinition} = this.getPathDefinitionMatching(path);
      if (_.isNil(pathDefinition)) {
        pathDefinition = createPathDefinition({path});
        this.pathDefinitions.push(pathDefinition);
      }
      innerRouters = innerRouters.filter(isSecureRouter);
      pathDefinition.innerRouters.push(...innerRouters);
    } else {
      innerRouters = [path, ...innerRouters].filter(isSecureRouter);
      for (const innerRouter of innerRouters) {
        this.bouncers.push(...innerRouter.bouncers);
        this.pathDefinitions.push(...innerRouter.pathDefinitions);
      }
    }

    let offset = this.stack.length;
    BaseRouter.prototype.use.apply(this, Router.arguments);

    // Inspired by https://github.com/expressjs/express/issues/2879#issuecomment-180088895
    /* so that in our monkey patch of process_params, we can know about the
     * path of this part of the route */
    if (pathIsString) {
      for (; offset < this.stack.length; offset++) {
        const layer = this.stack[offset];
        layer.__mountpath = path;
      }
    }
  };

  // Inspired by https://github.com/expressjs/express/issues/2879#issuecomment-180088895

  /* eslint-disable @typescript-eslint/naming-convention */
  process_params = (
    layer: {keys: Array<{name: string | number}>},
    _called: unknown,
    req: SecureRouterRequest,
  ): void => {
    const path: string = _.get(
      req,
      'route.path',
      _.get(req, 'route.regexp.source', _.get(layer, '__mountpath', '')),
    );

    if (req.matchedRoutes == null) req.matchedRoutes = [];
    req.__route = (req.__route || '') + path;

    const normalizedPath = path.endsWith('/') ? path.substring(0, path.length - 1) : path;
    if (!_.isEmpty(normalizedPath) && normalizedPath !== _.last(req.matchedRoutes)) {
      req.matchedRoutes.push(normalizedPath);
    }

    BaseRouter.prototype.process_params.apply(this, Router.arguments);
  };
  /* eslint-enable @typescript-eslint/naming-convention */

  bouncer({
    bouncer,
  }: {
    bouncer:
      | ((req: SecureRouterRequest, res: Response) => AccessStatus | Promise<AccessStatus>)
      | ((req: SecureRouterRequest) => AccessStatus | Promise<AccessStatus>);
  }): void {
    this.bouncers.push(bouncer);
  }

  /* returns a promise. runs all of the appropriate bouncers configured for this route.  */
  resolveCustomSecurity(req: SecureRouterRequest, res: Response, urlSegment: string): Promise<any> {
    return Promise.try(async () => {
      const bouncers: Array<
        | ((req: SecureRouterRequest, res: Response) => AccessStatus | Promise<AccessStatus>)
        | ((req: SecureRouterRequest) => AccessStatus | Promise<AccessStatus>)
      > = [...this.bouncers];
      const innerRouters: Router[] = [];

      const {pathDefinition, matchedUrlSegment} = this.getPathDefinitionMatching(
        urlSegment,
        req.method,
      );
      debug('Found matching path definitions', {pathDefinition, matchedUrlSegment});
      if (_.isObject(pathDefinition)) {
        urlSegment = urlSegment.substring(0, matchedUrlSegment.length);
        bouncers.push(...pathDefinition.bouncers);
        innerRouters.push(...pathDefinition.innerRouters);
      }

      const [bouncerResults, innerRouterResults] = await Promise.all([
        Promise.map(bouncers, (bouncer) => Promise.resolve(bouncer(req, res))),
        Promise.map(innerRouters, (innerRouter) =>
          innerRouter.resolveCustomSecurity(req, res, urlSegment),
        ),
      ]);
      return bouncerResults.concat(_.flatten(innerRouterResults));
    });
  }

  getPathDefinitionMatching(
    urlSegment: string,
    method?: string,
  ): {
    pathDefinition: NonNullable<
      {
        regexp: PathRegExp;
        innerRouters: Router[];
        bouncers: Array<
          | ((req: SecureRouterRequest, res: Response) => AccessStatus | Promise<AccessStatus>)
          | ((req: SecureRouterRequest) => AccessStatus | Promise<AccessStatus>)
        >;
        methods: string[];
      } & {
        path: string;
        innerRouters: Router[];
        bouncers?: Array<
          | ((req: SecureRouterRequest, res: Response) => AccessStatus | Promise<AccessStatus>)
          | ((req: SecureRouterRequest) => AccessStatus | Promise<AccessStatus>)
        >;
        methods?: string[];
      }
    > | null;
    matchedUrlSegment: string;
  } {
    let matches: RegExpExecArray | null, hasMethod: boolean;
    /* start with most specific path definition */
    this.pathDefinitions.sort(
      (a, b) => _.compact(b.path.split('/')).length - _.compact(a.path.split('/')).length,
    );
    for (const pathDefinition of this.pathDefinitions) {
      matches = pathDefinition.regexp.exec(urlSegment);
      hasMethod = _.isNil(method) || _.includes(pathDefinition.methods, method);
      if (_.isArray(matches) && matches.length > 0 && hasMethod) {
        return {pathDefinition, matchedUrlSegment: matches[0]};
      }
    }
    return {pathDefinition: null, matchedUrlSegment: ''};
  }
}

Router.AUTHORIZE = {value: AUTHORIZE};
Router.AUTHENTICATE = {value: AUTHENTICATE};
Router.DENY = {
  value: DENY,
  middleware(_req, res) {
    debug('Default DENY middleware responding with 401');
    res.sendStatus(401);
  },
};

function createPathDefinition(definition: {
  path: string;
  innerRouters?: Router[];
  bouncers?: Array<
    | ((
        req: SecureRouterRequest,
        res: Response,
      ) => AccessStatus | Promise<AccessStatus> | undefined)
    | ((req: SecureRouterRequest) => AccessStatus | Promise<AccessStatus> | undefined)
  >;
  methods?: string[];
}): NonNullable<
  {
    regexp: PathRegExp;
    innerRouters: Router[];
    bouncers: Array<
      | ((req: SecureRouterRequest, res: Response) => AccessStatus | Promise<AccessStatus>)
      | ((req: SecureRouterRequest) => AccessStatus | Promise<AccessStatus>)
    >;
    methods: string[];
  } & {
    path: string;
    innerRouters?: Router[];
    bouncers?: Array<
      | ((req: SecureRouterRequest, res: Response) => AccessStatus | Promise<AccessStatus>)
      | ((req: SecureRouterRequest) => AccessStatus | Promise<AccessStatus>)
    >;
    methods?: string[];
  }
> {
  return _.defaults({}, definition, {
    regexp: pathToRegexp(definition.path, {end: false, sensitive: true, strict: false}),
    innerRouters: [],
    bouncers: [],
    methods: http.METHODS,
  });
}

export default Router;
