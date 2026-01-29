using Application_Security_ASSGN2.Data;
using Microsoft.EntityFrameworkCore;

namespace Application_Security_ASSGN2.Middleware
{
    public class SessionValidationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<SessionValidationMiddleware> _logger;

        // Paths that don't require session validation
        private readonly string[] _excludedPaths = new[]
        {
            "/Account/Login",
            "/Account/Register",
            "/Account/ForgotPassword",
            "/Account/ResetPassword",
            "/Account/Verify2FA",
            "/Error",
            "/Home/Privacy",
            "/css",
            "/js",
            "/lib",
            "/uploads",
            "/favicon.ico",
            "/_framework",
            "/_blazor"
        };

        public SessionValidationMiddleware(RequestDelegate next, ILogger<SessionValidationMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context, ApplicationDbContext dbContext)
        {
            var path = context.Request.Path.Value?.ToLower() ?? "";

            // Skip validation for excluded paths
            if (_excludedPaths.Any(p => path.StartsWith(p.ToLower())))
            {
                await _next(context);
                return;
            }

            // Check if user has an active session
            var userId = context.Session.GetInt32("UserId");
            var sessionToken = context.Session.GetString("SessionToken");

            if (userId.HasValue && !string.IsNullOrEmpty(sessionToken))
            {
                // Validate session token against database
                var member = await dbContext.Members
                    .AsNoTracking()
                    .FirstOrDefaultAsync(m => m.Id == userId.Value);

                if (member == null || member.SessionToken != sessionToken)
                {
                    // Session is invalid - user logged in from another device/browser
                    _logger.LogWarning("Session invalidated for user {UserId}. Session token mismatch.", userId);
                    
                    context.Session.Clear();
                    
                    // Redirect to login with message
                    context.Response.Redirect("/Account/Login?message=session_expired");
                    return;
                }
            }

            await _next(context);
        }
    }

    public static class SessionValidationMiddlewareExtensions
    {
        public static IApplicationBuilder UseSessionValidation(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<SessionValidationMiddleware>();
        }
    }
}
