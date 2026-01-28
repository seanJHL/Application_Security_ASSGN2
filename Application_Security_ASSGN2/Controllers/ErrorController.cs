using Microsoft.AspNetCore.Mvc;

namespace Application_Security_ASSGN2.Controllers
{
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
            switch (statusCode)
            {
                case 404:
                    _logger.LogWarning("404 error occurred. Path: {Path}", HttpContext.Request.Path);
                    return View("404");
                case 403:
                    _logger.LogWarning("403 error occurred. Path: {Path}", HttpContext.Request.Path);
                    return View("403");
                case 500:
                    _logger.LogError("500 error occurred. Path: {Path}", HttpContext.Request.Path);
                    return View("500");
                default:
                    _logger.LogError("Error {StatusCode} occurred. Path: {Path}", statusCode, HttpContext.Request.Path);
                    return View("Index");
            }
        }

        [Route("Error")]
        public IActionResult Error()
        {
            _logger.LogError("An unhandled error occurred");
            return View("500");
        }
    }
}
