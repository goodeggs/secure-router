import _ from 'lodash';
import express from 'express';

import Router from './router';

const router = new Router();

router.use(function (req, res, next) {
  console.log(req.method, req.url);
  next();
});

/* enforce that someone explicitly has to 'ALLOW' and nobody can 'DENY' */
router.use(function (req, res, next) {
  router.resolveCustomSecurity(req)
  .then(function (result) {
    console.log(result);
    if (result === 'ALLOW') return next();
    return res.sendStatus(405);
  });
});

router.withSecurity('/foo', _.constant('ALLOW'))
.get('/foo', function (req, res) {
  res.send('foo');
});

router.get('/bar', function (req, res) {
  res.send('bar');
});

const app = express();

app.use(router);

export default app;
