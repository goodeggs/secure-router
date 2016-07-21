'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _router = require('router');

var _router2 = _interopRequireDefault(_router);

var _bluebird = require('bluebird');

var _bluebird2 = _interopRequireDefault(_bluebird);

var _lodash = require('lodash');

var _lodash2 = _interopRequireDefault(_lodash);

var _pathToRegexp = require('path-to-regexp');

var _pathToRegexp2 = _interopRequireDefault(_pathToRegexp);

var _http = require('http');

var _http2 = _interopRequireDefault(_http);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _toConsumableArray(arr) { if (Array.isArray(arr)) { for (var i = 0, arr2 = Array(arr.length); i < arr.length; i++) { arr2[i] = arr[i]; } return arr2; } else { return Array.from(arr); } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var Router = function (_BaseRouter) {
  _inherits(Router, _BaseRouter);

  function Router() {
    var _Object$getPrototypeO;

    _classCallCheck(this, Router);

    for (var _len = arguments.length, args = Array(_len), _key = 0; _key < _len; _key++) {
      args[_key] = arguments[_key];
    }

    var _this = _possibleConstructorReturn(this, (_Object$getPrototypeO = Object.getPrototypeOf(Router)).call.apply(_Object$getPrototypeO, [this].concat(args)));

    _this.bouncers = [];
    _this.pathDefinitions = [];
    _this.innerRouters = [];
    return _this;
  }

  _createClass(Router, [{
    key: 'bounceRequests',
    value: function bounceRequests() {
      var router = this;
      router.use(function (req, res, next) {
        router.resolveCustomSecurity(req, req.url).then(function (results) {
          function someResultsMatch(test) {
            return _lodash2.default.some(results, function (result) {
              return result === test;
            });
          }
          function noResultsMatch(test) {
            return _lodash2.default.every(results, function (result) {
              return result !== test;
            });
          }

          if (someResultsMatch('DENY')) return res.sendStatus(401);
          if (noResultsMatch('AUTHENTICATE')) return res.sendStatus(401);
          if (noResultsMatch('AUTHORIZE')) return res.sendStatus(403);
          return next();
        });
      });
      return router;
    }
  }, {
    key: 'secureSubpath',
    value: function secureSubpath(params) {
      if (_lodash2.default.isNil(params.path)) throw new Error('Must pass a path to secureSubpath');

      var bouncers = params.bouncers;
      if (_lodash2.default.isNil(bouncers)) bouncers = [];
      if (_lodash2.default.isFunction(params.bouncer)) bouncers.push(params.bouncer);

      var innerRouter = new Router();
      this.pathDefinitions.push(createPathDefinition({
        path: params.path,
        innerRouters: [innerRouter],
        bouncers: bouncers
      }));
      this.use(params.path, innerRouter);
      return innerRouter;
    }
  }, {
    key: 'secureEndpoint',
    value: function secureEndpoint(params) {
      if (_lodash2.default.isNil(params.path)) throw new Error('Must pass a path to secureEndpoint');
      if (_lodash2.default.isNil(params.method)) throw new Error('Must pass a method to secureEndpoint');

      var bouncers = params.bouncers;
      if (_lodash2.default.isNil(bouncers)) bouncers = [];
      if (_lodash2.default.isFunction(params.bouncer)) bouncers.push(params.bouncer);

      var middleware = params.middleware;
      if (_lodash2.default.isNil(middleware)) throw new Error('Must pass a middlware to secureEndpoint');
      if (_lodash2.default.isFunction(middleware)) middleware = [middleware];

      this.pathDefinitions.push(createPathDefinition({
        path: params.path,
        bouncers: bouncers,
        methods: [params.method.toUpperCase()]
      }));

      /* actually mount the route */
      this[params.method.toLowerCase()].apply(this, [params.path].concat(_toConsumableArray(middleware)));
      return this;
    }
  }, {
    key: 'use',
    value: function use(path) {
      for (var _len2 = arguments.length, innerRouters = Array(_len2 > 1 ? _len2 - 1 : 0), _key2 = 1; _key2 < _len2; _key2++) {
        innerRouters[_key2 - 1] = arguments[_key2];
      }

      if (_lodash2.default.isString(path)) {
        var _pathDefinition$inner;

        var _getPathDefinitionMat = this.getPathDefinitionMatching(path);

        var pathDefinition = _getPathDefinitionMat.pathDefinition;

        if (_lodash2.default.isNil(pathDefinition)) {
          pathDefinition = createPathDefinition({ path: path });
          this.pathDefinitions.push(pathDefinition);
        }
        innerRouters = innerRouters.filter(function (router) {
          return _lodash2.default.isFunction(router.resolveCustomSecurity);
        });
        (_pathDefinition$inner = pathDefinition.innerRouters).push.apply(_pathDefinition$inner, _toConsumableArray(innerRouters));
      }
      _router2.default.prototype.use.apply(this, arguments);
    }
  }, {
    key: 'bouncer',
    value: function bouncer(_bouncer) {
      this.bouncers.push(_bouncer);
    }

    /* returns a promise. runs all of the appropriate bouncers configured for this route.  */

  }, {
    key: 'resolveCustomSecurity',
    value: function resolveCustomSecurity(req, urlSegment) {
      var _this2 = this;

      return _bluebird2.default.try(function () {
        var bouncerResults = [];
        var bouncers = [].concat(_toConsumableArray(_this2.bouncers));
        var innerRouters = [];

        var _getPathDefinitionMat2 = _this2.getPathDefinitionMatching(urlSegment, req.method);

        var pathDefinition = _getPathDefinitionMat2.pathDefinition;
        var matchedUrlSegment = _getPathDefinitionMat2.matchedUrlSegment;

        if (_lodash2.default.isObject(pathDefinition)) {
          urlSegment = urlSegment.substr(matchedUrlSegment.length);
          bouncers.push.apply(bouncers, _toConsumableArray(pathDefinition.bouncers));
          innerRouters.push.apply(innerRouters, _toConsumableArray(pathDefinition.innerRouters));
        }

        return _bluebird2.default.all([_bluebird2.default.map(bouncers, function (bouncer) {
          return _bluebird2.default.resolve(bouncer(req)).then(function (result) {
            return bouncerResults.push(result);
          });
        }), _bluebird2.default.map(innerRouters, function (innerRouter) {
          return innerRouter.resolveCustomSecurity(req, urlSegment).then(function (results) {
            return bouncerResults.push.apply(bouncerResults, _toConsumableArray(results));
          });
        })]).then(function () {
          return bouncerResults;
        });
      });
    }
  }, {
    key: 'getPathDefinitionMatching',
    value: function getPathDefinitionMatching(urlSegment, method) {
      var matches = void 0,
          hasMethod = void 0;
      var _iteratorNormalCompletion = true;
      var _didIteratorError = false;
      var _iteratorError = undefined;

      try {
        for (var _iterator = this.pathDefinitions[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
          var pathDefinition = _step.value;

          matches = pathDefinition.regexp.exec(urlSegment);
          hasMethod = _lodash2.default.isNil(method) || _lodash2.default.includes(pathDefinition.methods, method);
          if (_lodash2.default.isArray(matches) && matches.length > 0 && hasMethod) {
            return { pathDefinition: pathDefinition, matchedUrlSegment: matches[0] };
          }
        }
      } catch (err) {
        _didIteratorError = true;
        _iteratorError = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion && _iterator.return) {
            _iterator.return();
          }
        } finally {
          if (_didIteratorError) {
            throw _iteratorError;
          }
        }
      }

      return { pathDefinition: null, matchedUrlSegment: '' };
    }
  }]);

  return Router;
}(_router2.default);

exports.default = Router;


function createPathDefinition(definition) {
  return _lodash2.default.defaults({}, definition, {
    regexp: (0, _pathToRegexp2.default)(definition.path, { end: false, sensitive: true, strict: false }),
    innerRouters: [],
    bouncers: [],
    methods: _http2.default.METHODS
  });
}
module.exports = exports['default'];