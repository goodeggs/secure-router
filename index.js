import BaseRouter from 'router';
import Promise from 'bluebird';
import _ from 'lodash';
import pathToRegexp from 'path-to-regexp';
import http from 'http';

export default class Router extends BaseRouter {
  constructor (...args) {
    super(...args);
    this.pathDefinitions = [];
    this.innerRouters = [];
  }

  bounceRequests () {
    const router = this;
    router.use(function (req, res, next) {
      router.resolveCustomSecurity(req, req.url)
      .then(function (result) {
        if (result === 'ALLOW') return next();
        return res.sendStatus(401);
      });
    });
    return router;
  }

  secureSubpath (params) {
    if (_.isNil(params.path)) throw new Error('Must pass a path to secureEndpoint');

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
    if (_.isString(path)) {
      let {pathDefinition} = this.getPathDefinitionMatching(path);
      if (_.isNil(pathDefinition)) {
        pathDefinition = createPathDefinition({path});
        this.pathDefinitions.push(pathDefinition);
      }
      innerRouters = innerRouters.filter((router) => _.isFunction(router.resolveCustomSecurity));
      pathDefinition.innerRouters.push(...innerRouters);
    }
    BaseRouter.prototype.use.apply(this, arguments);
  }

  /* returns a promise. runs all of the appropriate middlewares configured for this route.
   *
   * if any return "DENY", then return the first "DENY".
   * if none return "DENY" and one returns "ALLOW", return "ALLOW".
   * otherwise return undefined.
   */
  resolveCustomSecurity (req, urlSegment) {
    return Promise.try(() => {
      const {pathDefinition, matchedUrlSegment} = this.getPathDefinitionMatching(urlSegment, req.method);
      if (!pathDefinition) return Promise.resolve();

      urlSegment = urlSegment.substr(matchedUrlSegment.length);

      return Promise.mapSeries(pathDefinition.bouncers, function (bouncer) {
        return Promise.resolve(bouncer(req))
        .then(function (result) {
          if (result === 'DENY') throw new Error();
          return result;
        });
      })
      .then(function (resultsForCurrentPath) {
        return Promise.mapSeries(pathDefinition.innerRouters, function (innerRouter) {
          return innerRouter.resolveCustomSecurity(req, urlSegment)
          .then(function (result) {
            if (result === 'DENY') throw new Error();
            return result;
          });
        })
        .then(function (resultsForInnerRouters) {
          return resultsForCurrentPath.concat(resultsForInnerRouters);
        });
      })
      .then(function (results) {
        if (_.some(results, (result) => result === 'ALLOW')) return 'ALLOW';
      })
      .catch(_.constant('DENY'));
    });
  }

  getPathDefinitionMatching (urlSegment, method) {
    let matches, hasMethod;
    for (const pathDefinition of this.pathDefinitions) {
      matches = pathDefinition.regexp.exec(urlSegment);
      hasMethod = _.isNil(method) || _.includes(pathDefinition.methods, method);
      if (_.isArray(matches) && matches.length > 0 && hasMethod) {
        return {pathDefinition, matchedUrlSegment: matches[0]};
      }
    }
    return {pathDefinition: null};
  }
}

function createPathDefinition (definition) {
  return _.defaults({}, definition, {
    regexp: pathToRegexp(definition.path, {end: false, sensitive: true, strict: false}),
    innerRouters: [],
    bouncers: [],
    methods: http.METHODS,
  });
}
