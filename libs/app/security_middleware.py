# libs/app/security_middleware.py
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from typing import Callable, Awaitable


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Добавляет стандартные заголовки безопасности в ответы.
    """

    async def dispatch(
            self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)

        docs_url = getattr(request.app, "docs_url", None)
        redoc_url = getattr(request.app, "redoc_url", None)

        # Apply a less restrictive policy for documentation pages to allow them to render correctly.
        if (docs_url and request.url.path == docs_url) or \
           (redoc_url and request.url.path == redoc_url):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
                "img-src 'self' data:;"
            )
        else:
            # Apply a strict policy for all other application pages.
            response.headers["Content-Security-Policy"] = "default-src 'none'"

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"

        return response