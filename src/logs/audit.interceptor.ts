import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import type { Request } from 'express';
import { Observable, catchError, tap, throwError } from 'rxjs';
import { LogsService } from './logs.service';
import { extractIp, extractUa } from './ua-parser';

@Injectable()
export class AuditInterceptor implements NestInterceptor {
  constructor(private readonly logs: LogsService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const req = context.switchToHttp().getRequest<Request & { user?: any }>();
    const method = req.method?.toUpperCase();
    if (!method || method === 'GET' || method === 'OPTIONS') return next.handle();

    const path = req.originalUrl || req.url;
    if (path.includes('/auth/login') || path.includes('/auth/refresh')) {
      return next.handle();
    }

    const started = Date.now();
    return next.handle().pipe(
      tap(() => this.write(req, null, Date.now() - started)),
      catchError(err => {
        this.write(req, err, Date.now() - started);
        return throwError(() => err);
      }),
    );
  }

  private write(req: Request & { user?: any }, err: any, durationMs: number) {
    const params = (req as any).params || {};
    const body = this.maskBody((req as any).body);
    const action = err
      ? `${req.method.toLowerCase()}.error`
      : `${req.method.toLowerCase()}.${this.pathAction(req.path || req.url)}`;

    this.logs.writeAudit({
      userId: req.user?.id ?? null,
      username: req.user?.username ?? null,
      action,
      method: req.method,
      path: req.originalUrl || req.url,
      targetId: params.id ?? params.websiteId ?? null,
      ip: extractIp(req),
      userAgent: extractUa(req),
      metadata: {
        params,
        body,
        durationMs,
        status: err?.status ?? err?.response?.statusCode ?? 'ok',
      },
    }).catch(() => {});
  }

  private pathAction(path: string): string {
    return path
      .replace(/^\/api\//, '')
      .replace(/^\//, '')
      .replace(/[/:]+/g, '.')
      .replace(/\.+/g, '.')
      .replace(/\.$/, '') || 'request';
  }

  private maskBody(body: unknown): unknown {
    if (!body || typeof body !== 'object') return body;
    const makeCopy = (source: object): object =>
      source instanceof Date
        ? new Date(source.getTime())
        : Array.isArray(source)
          ? new Array<unknown>(source.length)
          : {};
    const clone = makeCopy(body);
    const copies = new WeakMap<object, object>([[body, clone]]);
    const pending: [object, object][] = [[body, clone]];

    // Walk iteratively so deeply nested JSON cannot exhaust the call stack.
    while (pending.length) {
      const [source, target] = pending.pop()!;
      for (const [key, value] of Object.entries(source) as [
        string,
        unknown,
      ][]) {
        let masked = value;
        if (/password|token|secret|apiKey/i.test(key)) {
          masked = '[redacted]';
        } else if (value && typeof value === 'object') {
          let copy = copies.get(value);
          if (!copy) {
            copy = makeCopy(value);
            copies.set(value, copy);
            pending.push([value, copy]);
          }
          masked = copy;
        }
        // An own __proto__ JSON key must remain data, not a prototype setter.
        Object.defineProperty(target, key, {
          value: masked,
          enumerable: true,
          configurable: true,
          writable: true,
        });
      }
    }
    return clone;
  }
}
