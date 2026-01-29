using Microsoft.AspNetCore.Mvc;

namespace Application_Security_ASSGN2.Controllers
{
    /// <summary>
    /// Handles HTTP error responses with custom error pages.
    /// Provides user-friendly error messages without exposing server details.
    /// 
    /// HTTP Status Code Reference:
    /// - 400 Bad Request: The server cannot process the request due to client error
    /// - 401 Unauthorized: Authentication is required but not provided or invalid
    /// - 403 Forbidden: Server understood request but refuses to authorize it
    /// - 404 Not Found: The requested resource could not be found
    /// - 405 Method Not Allowed: HTTP method not supported for this resource
    /// - 408 Request Timeout: Server timed out waiting for the request
    /// - 429 Too Many Requests: Rate limiting - too many requests in given time
    /// - 500 Internal Server Error: Unexpected server error
    /// - 501 Not Implemented: Server does not support the functionality required
    /// - 502 Bad Gateway: Invalid response from upstream server
    /// - 503 Service Unavailable: Server temporarily unable to handle request
    /// </summary>
    public class ErrorController : Controller
    {
        private readonly ILogger<ErrorController> _logger;

        public ErrorController(ILogger<ErrorController> logger)
        {
            _logger = logger;
        }

        [Route("Error/{statusCode}")]
        public IActionResult HttpStatusCodeHandler(int statusCode)
        {
            // Set the response status code
            Response.StatusCode = statusCode;

            // Log the error with appropriate level
            var originalPath = HttpContext.Request.Query["originalPath"].FirstOrDefault() 
                ?? HttpContext.Request.Path.ToString();
            
            switch (statusCode)
            {
                case 400:
                    _logger.LogWarning("400 Bad Request. Path: {Path}, IP: {IP}", 
                        originalPath, GetClientIp());
                    return View("400");
                    
                case 401:
                    _logger.LogWarning("401 Unauthorized. Path: {Path}, IP: {IP}", 
                        originalPath, GetClientIp());
                    return View("401");
                    
                case 403:
                    _logger.LogWarning("403 Forbidden. Path: {Path}, IP: {IP}", 
                        originalPath, GetClientIp());
                    return View("403");
                    
                case 404:
                    _logger.LogWarning("404 Not Found. Path: {Path}, IP: {IP}", 
                        originalPath, GetClientIp());
                    return View("404");
                    
                case 405:
                    _logger.LogWarning("405 Method Not Allowed. Path: {Path}, IP: {IP}", 
                        originalPath, GetClientIp());
                    return View("405");
                    
                case 429:
                    _logger.LogWarning("429 Too Many Requests. Path: {Path}, IP: {IP}", 
                        originalPath, GetClientIp());
                    return View("429");
                    
                case 500:
                    _logger.LogError("500 Internal Server Error. Path: {Path}, IP: {IP}", 
                        originalPath, GetClientIp());
                    return View("500");
                    
                case 503:
                    _logger.LogError("503 Service Unavailable. Path: {Path}, IP: {IP}", 
                        originalPath, GetClientIp());
                    return View("503");
                    
                default:
                    _logger.LogError("HTTP {StatusCode} Error. Path: {Path}, IP: {IP}", 
                        statusCode, originalPath, GetClientIp());
                    ViewBag.StatusCode = statusCode;
                    return View("Index");
            }
        }

        [Route("Error")]
        public IActionResult Error()
        {
            Response.StatusCode = 500;
            _logger.LogError("Unhandled exception occurred. IP: {IP}", GetClientIp());
            return View("500");
        }

        private string GetClientIp()
        {
            return HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown";
        }
    }
}
