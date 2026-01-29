using System.Net;

namespace Application_Security_ASSGN2.Middleware
{
    /// <summary>
    /// Global exception handling middleware.
    /// Catches all unhandled exceptions and returns user-friendly error pages
    /// without exposing sensitive information like stack traces.
    /// </summary>
    public class ExceptionHandlingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ExceptionHandlingMiddleware> _logger;
        private readonly IWebHostEnvironment _environment;

        public ExceptionHandlingMiddleware(
            RequestDelegate next,
            ILogger<ExceptionHandlingMiddleware> logger,
            IWebHostEnvironment environment)
        {
            _next = next;
            _logger = logger;
            _environment = environment;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                await HandleExceptionAsync(context, ex);
            }
        }

        private async Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            // Log the full exception details for developers
            _logger.LogError(exception, 
                "Unhandled exception occurred. Request: {Method} {Path}. User: {User}. IP: {IP}",
                context.Request.Method,
                context.Request.Path,
                context.User?.Identity?.Name ?? "Anonymous",
                context.Connection.RemoteIpAddress?.ToString() ?? "Unknown");

            // Determine the appropriate status code based on exception type
            var statusCode = exception switch
            {
                ArgumentException => (int)HttpStatusCode.BadRequest,              // 400
                UnauthorizedAccessException => (int)HttpStatusCode.Unauthorized,  // 401
                KeyNotFoundException => (int)HttpStatusCode.NotFound,             // 404
                InvalidOperationException => (int)HttpStatusCode.Conflict,        // 409
                NotImplementedException => (int)HttpStatusCode.NotImplemented,    // 501
                _ => (int)HttpStatusCode.InternalServerError                      // 500
            };

            // Clear any existing response
            context.Response.Clear();
            context.Response.StatusCode = statusCode;

            // Redirect to the appropriate error page
            // This prevents exposing any stack traces or internal details
            if (!context.Response.HasStarted)
            {
                context.Response.Redirect($"/Error/{statusCode}");
            }

            await Task.CompletedTask;
        }
    }

    public static class ExceptionHandlingMiddlewareExtensions
    {
        public static IApplicationBuilder UseGlobalExceptionHandler(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<ExceptionHandlingMiddleware>();
        }
    }
}
