import BaseRouter from 'router';
import Promise from 'bluebird';
import _ from 'lodash';
import pathToRegexp from 'path-to-regexp';
import http from 'http';

export default class Router extends BaseRouter {
  constructor (...args) {
    super(...args);
    this.bouncers = [];
    this.pathDefinitions = [];
  }

  bounceRequests () {
    const router = this;
    router.use(function (req, res, next) {
      router.resolveCustomSecurity(req, res, req.url)
      .then(function (results) {
        function someResultsMatch (test) {
          return _.some(results, (result) => result === test);
        }
        function noResultsMatch (test) {
          return _.every(results, (result) => result !== test);
        }

        if (someResultsMatch('DENY')) return res.sendStatus(401);
        if (noResultsMatch('AUTHENTICATE')) return res.sendStatus(401);
        if (noResultsMatch('AUTHORIZE')) return res.sendStatus(403);
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
      const bouncerResults = [];
      const bouncers = [...this.bouncers];
      const innerRouters = [];

      const {pathDefinition, matchedUrlSegment} = this.getPathDefinitionMatching(urlSegment, req.method);
      if (_.isObject(pathDefinition)) {
        urlSegment = urlSegment.substr(matchedUrlSegment.length);
        bouncers.push(...pathDefinition.bouncers);
        innerRouters.push(...pathDefinition.innerRouters);
      }

      return Promise.all([
        Promise.map(bouncers, function (bouncer) {
          return Promise.resolve(bouncer(req, res))
          .then((result) => bouncerResults.push(result));
        }),

        Promise.map(innerRouters, function (innerRouter) {
          return innerRouter.resolveCustomSecurity(req, res, urlSegment)
          .then((results) => bouncerResults.push(...results));
        }),
      ])
      .then(() => bouncerResults);
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
    return {pathDefinition: null, matchedUrlSegment: ''};
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
