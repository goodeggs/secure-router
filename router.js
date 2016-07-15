import BaseRouter from 'router';
import Promise from 'bluebird';
import _ from 'lodash';
import pathToRegexp from 'path-to-regexp';

export default class Router extends BaseRouter {
  constructor (...args) {
    super(...args);
    this.pathDefinitions = [];
    this.innerRouters = [];
  }

  getRequireOptInMiddleware () {
    const router = this;
    return function (req, res, next) {
      router.resolveCustomSecurity(req, req.url)
      .then(function (result) {
        if (result === 'ALLOW') return next();
        return res.sendStatus(405);
      });
    };
  }

  withSecurity (path, ...resolvers) {
    const innerRouter = new Router();
    this.pathDefinitions.push(createPathDefinition({path, innerRouters: [innerRouter], resolvers}));
    this.use(path, innerRouter);
    return innerRouter;
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
      const {pathDefinition, matchedUrlSegment} = this.getPathDefinitionMatching(urlSegment);
      if (!pathDefinition) return Promise.resolve();

      urlSegment = urlSegment.substr(matchedUrlSegment.length);

      return Promise.mapSeries(pathDefinition.resolvers, function (resolver) {
        return Promise.resolve(resolver(req))
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

  getPathDefinitionMatching (urlSegment) {
    let matches;
    for (const pathDefinition of this.pathDefinitions) {
      matches = pathDefinition.regexp.exec(urlSegment);
      if (_.isArray(matches) && matches.length > 0) {
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
    resolvers: [],
  });
}
