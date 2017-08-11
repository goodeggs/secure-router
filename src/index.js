import BaseRouter from 'router';
import Promise from 'bluebird';
import _ from 'lodash';
import configureDebug from 'debug';
import http from 'http';
import pathToRegexp from 'path-to-regexp';
import url from 'url';
import async from 'async';

const debug = configureDebug('secure-router');

export default class Router extends BaseRouter {
  constructor (...args) {
    super(...args);
    this.bouncers = [];
    this.pathDefinitions = [];
  }

  static denyWith (params, i) {
    let middleware;

    if (_.isFunction(params)) {
      debug('Creating denial with a provided middleware function');
      middleware = params;
    } else if (_.isObject(params)) {
      debug('Creating denial with params', params);
      middleware = (req, res) => {
        debug('Responding to request with procedural denyWith middleware');
        res.status(_.get(params, 'statusCode', 401));
        res.send(params.payload);
      };
    }

    return _.assign({}, Router.DENY, {middleware, i});
  }

  bounceRequests () {
    const router = this;
    router.use(function (req, res, next) {
      const parsedUrl = url.parse(req.url);
      router.resolveCustomSecurity(req, res, parsedUrl.pathname)
      .then(function (results) {
        function match (result, expectedValue) {
          return _.isObject(result) && result.value === expectedValue;
        }

        function someResultsMatch (expectedValue) {
          return _.some(results, (result) => match(result, expectedValue));
        }
        function noResultsMatch (expectedValue) {
          return _.every(results, (result) => !match(result, expectedValue));
        }

        if (someResultsMatch(DENY)) {
          const denyResults = _.filter(results, (result) => match(result, DENY));
          debug('Got one or more DENY', {denyResults});
          // TODO(@max) sort here???
          async.eachSeries(
            _.map(denyResults, 'middleware'),
            (middleware, callback) => {
              try {
                middleware(req, res, callback);
              } catch (err) {
                debug('DENY middleware threw a synchronous error', err.stack);
                callback(err);
              }
            },
            next
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
        return next();
      });
    });
    return router;
  }

  secureSubpath (params) {
    if (_.isNil(params.path)) throw new Error('Must pass a path to secureSubpath');

    let bouncers = params.bouncers;
    if (_.isNil(bouncers)) bouncers = [];
    if (_.isFunction(params.bouncer)) bouncers.push(params.bouncer);

    const innerRouter = new Router();
    this.pathDefinitions.push(createPathDefinition({
      path: params.path,
      innerRouters: [innerRouter],
      bouncers,
    }));
    this.use(params.path, innerRouter);
    return innerRouter;
  }

  secureEndpoint (params) {
    if (_.isNil(params.path)) throw new Error('Must pass a path to secureEndpoint');
    if (_.isNil(params.method)) throw new Error('Must pass a method to secureEndpoint');

    let bouncers = params.bouncers;
    if (_.isNil(bouncers)) bouncers = [];
    if (_.isFunction(params.bouncer)) bouncers.push(params.bouncer);

    let middleware = params.middleware;
    if (_.isNil(middleware)) throw new Error('Must pass a middlware to secureEndpoint');
    if (_.isFunction(middleware)) middleware = [middleware];

    this.pathDefinitions.push(createPathDefinition({
      path: params.path,
      bouncers,
      methods: [params.method.toUpperCase()],
    }));

    /* actually mount the route */
    this[params.method.toLowerCase()](params.path, ...middleware);
    return this;
  }

  use (path, ...innerRouters) {
    function isSecureRouter (router) {
      return _.isFunction(router.resolveCustomSecurity);
    }

    if (_.isString(path)) {
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
    BaseRouter.prototype.use.apply(this, arguments);
  }

  bouncer (bouncer) {
    this.bouncers.push(bouncer);
  }

  /* returns a promise. runs all of the appropriate bouncers configured for this route.  */
  resolveCustomSecurity (req, res, urlSegment) {
    return Promise.try(() => {
      const bouncers = [...this.bouncers];
      const innerRouters = [];

      const {pathDefinition, matchedUrlSegment} = this.getPathDefinitionMatching(urlSegment, req.method);
      debug('Found matching path definitions', {pathDefinition, matchedUrlSegment});
      if (_.isObject(pathDefinition)) {
        urlSegment = urlSegment.substr(matchedUrlSegment.length);
        bouncers.push(...pathDefinition.bouncers);
        innerRouters.push(...pathDefinition.innerRouters);
      }

      return Promise.all([
        Promise.map(bouncers, (bouncer) => Promise.resolve(bouncer(req, res))),
        Promise.map(innerRouters, (innerRouter) =>
          innerRouter.resolveCustomSecurity(req, res, urlSegment)
        ),
      ])
      .then(([bouncerResults, innerRouterResults]) => bouncerResults.concat(_.flatten(innerRouterResults)));
    });
  }

  getPathDefinitionMatching (urlSegment, method) {
    let matches, hasMethod;
    /* start with most specific path definition */
    this.pathDefinitions.sort((a, b) =>
      _.compact(b.path.split('/')).length - _.compact(a.path.split('/')).length
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

const AUTHORIZE = 'AUTHORIZE';
const AUTHENTICATE = 'AUTHENTICATE';
const DENY = 'DENY';

Router.AUTHORIZE = {value: AUTHORIZE};
Router.AUTHENTICATE = {value: AUTHENTICATE};
Router.DENY = {
  value: DENY,
  middleware (req, res) {
    debug('Default DENY middleware responding with 401');
    res.sendStatus(401);
  },
};

function createPathDefinition (definition) {
  return _.defaults({}, definition, {
    regexp: pathToRegexp(definition.path, {end: false, sensitive: true, strict: false}),
    innerRouters: [],
    bouncers: [],
    methods: http.METHODS,
  });
}

module.exports = Router;
