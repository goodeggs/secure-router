// (@camillateodoro) copied from https://github.com/goodeggs/goodeggs-authentication-tokens/blob/master/src/types/router.d.ts

// Stolen from https://github.com/pillarjs/router/issues/48#issuecomment-881248412
declare module 'router' {
  import type {NextFunction, NextHandleFunction} from 'connect';
  import {Request, Response} from 'express';
  import type {IncomingMessage, ServerResponse} from 'http';

  // Obviously, we don't control what other libraries call things.
  /* eslint-disable @typescript-eslint/naming-convention */

  export type Path = string | RegExp | Array<string | RegExp>;

  export type ErrorHandlerFunction = (
    err: Error,
    req: Request,
    res: Response,
    next: NextFunction,
  ) => void;

  export namespace Router {
    export interface RouteType {
      new (path: string): Route;
      prototype: Route;
    }

    type Method = 'all' | 'head' | 'get' | 'post' | 'delete' | 'put' | 'patch' | 'options';

    export type Route = {readonly path: Path} & Record<
      Method,
      (middleware: NextHandleFunction, ...middlewares: NextHandleFunction[]) => Route
    >;

    export interface Options {
      caseSensitive?: boolean;
      strict?: boolean;
      mergeParams?: <C extends Record<string, unknown>, P extends Record<string, unknown>>(
        currentParams: C,
        parentParams: P,
      ) => Record<string, unknown>;
    }

    export type ParamCallback<K = string | number> = (
      req: IncomingMessage,
      res: ServerResponse,
      next: NextFunction,
      value: unknown,
      name: K,
    ) => unknown;

    interface InnerRouter extends NextHandleFunction {
      route(path: Path): Route;
      param: <K extends string | number>(name: K, fn: ParamCallback<K>) => this;
      process_params: <K extends string | number>(
        layer: {keys: Array<{name: K}>},
        called: Record<K, {match: unknown; value: unknown; error: unknown}>,
        req: {matchedRoutes: string[]; __route: string},
      ) => void;
    }

    export type Router = InnerRouter &
      Record<
        'use' | Method,
        {
          (
            path: Path,
            middleware: NextHandleFunction,
            ...middlewares: NextHandleFunction[]
          ): Router;
          (middleware: NextHandleFunction, ...middlewares: NextHandleFunction[]): Router;
        }
      >;

    interface RouterType {
      new (options?: Options): Router;
      (options?: Options): Router;
      Route: RouteType;
      prototype: Router;
    }
  }

  export type RouterType = Router.RouterType;
  export type RouterMethod = Router.Method;
  const Router: RouterType;
  export default Router;

  /* eslint-enable @typescript-eslint/naming-convention */
}
