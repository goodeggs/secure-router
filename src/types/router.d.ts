// (@camillateodoro) copied from https://github.com/goodeggs/goodeggs-authentication-tokens/blob/master/src/types/router.d.ts

// Stolen from https://github.com/pillarjs/router/issues/48#issuecomment-881248412
declare module 'router' {
  import type {NextFunction, NextHandleFunction} from 'connect';
  import type {IncomingMessage, ServerResponse} from 'http';
  import {Request, RequestHandler, Response} from 'express';

  export type ErrorHandleFunction = (
    err: Error,
    req: Request,
    res: Response,
    next: NextFunction,
  ) => void;

  interface SecureRouterRequest extends Request {
    matchedRoutes?: string[];
    __route: string;
  }

  // Obviously, we don't control what other libraries call things.
  /* eslint-disable @typescript-eslint/naming-convention */

  export type Path = string | RegExp | Array<string | RegExp>;

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
        req: SecureRouterRequest,
      ) => void;
    }

    export type Router = InnerRouter &
      Record<
        'use' | Method,
        {
          (
            path: Path | RequestHandler | ErrorHandleFunction,
            ...middleware: Array<NextHandleFunction | RequestHandler | ErrorHandleFunction>
          ): Router;
          (
            middleware: NextHandleFunction | RequestHandler | ErrorHandleFunction,
            ...middlewares: Array<NextHandleFunction | RequestHandler | ErrorHandleFunction>
          ): Router;
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
