namespace Application_Security_ASSGN2.Middleware
{
    /// <summary>
    /// Middleware to add security headers to all responses.
    /// Protects against XSS, clickjacking, MIME sniffing, and other attacks.
    /// </summary>
    public class SecurityHeadersMiddleware
    {
        private readonly RequestDelegate _next;

        public SecurityHeadersMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Add security headers before processing the request
            var headers = context.Response.Headers;

            // X-Content-Type-Options: Prevents MIME type sniffing
            // Stops browsers from interpreting files as a different MIME type
            headers["X-Content-Type-Options"] = "nosniff";

            // X-Frame-Options: Prevents clickjacking attacks
            // DENY = page cannot be displayed in a frame
            headers["X-Frame-Options"] = "DENY";

            // X-XSS-Protection: Enables browser's XSS filter (legacy but still useful)
            // 1; mode=block = enable XSS filter and block the page if attack detected
            headers["X-XSS-Protection"] = "1; mode=block";

            // Referrer-Policy: Controls how much referrer info is sent
            // strict-origin-when-cross-origin = send full URL for same-origin, only origin for cross-origin
            headers["Referrer-Policy"] = "strict-origin-when-cross-origin";

            // Permissions-Policy: Restricts browser features (replaces Feature-Policy)
            headers["Permissions-Policy"] = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()";

            // Content-Security-Policy: Prevents XSS and data injection attacks
            // Defines approved sources of content that browsers may load
            headers["Content-Security-Policy"] = 
                "default-src 'self'; " +
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://www.google.com https://www.gstatic.com; " +
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; " +
                "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; " +
                "img-src 'self' data: https:; " +
                "frame-src https://www.google.com; " +
                "connect-src 'self' https://www.google.com; " +
                "form-action 'self'; " +
                "frame-ancestors 'none'; " +
                "base-uri 'self'; " +
                "object-src 'none';";

            // Strict-Transport-Security: Forces HTTPS connections
            // max-age=31536000 = 1 year, includeSubDomains = apply to all subdomains
            headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";

            // X-Permitted-Cross-Domain-Policies: Restricts Adobe Flash/Acrobat
            headers["X-Permitted-Cross-Domain-Policies"] = "none";

            // Cache-Control: Prevent caching of sensitive pages
            if (!context.Request.Path.StartsWithSegments("/lib") && 
                !context.Request.Path.StartsWithSegments("/css") && 
                !context.Request.Path.StartsWithSegments("/js"))
            {
                headers["Cache-Control"] = "no-store, no-cache, must-revalidate, proxy-revalidate";
                headers["Pragma"] = "no-cache";
                headers["Expires"] = "0";
            }

            await _next(context);
        }
    }

    public static class SecurityHeadersMiddlewareExtensions
    {
        public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<SecurityHeadersMiddleware>();
        }
    }
}
