using System.Text.RegularExpressions;
using System.Web;

namespace Application_Security_ASSGN2.Services
{
    /// <summary>
    /// Service for sanitizing user input to prevent XSS and injection attacks.
    /// </summary>
    public interface IInputSanitizationService
    {
        /// <summary>
        /// Sanitizes input by removing potentially dangerous characters and patterns.
        /// </summary>
        string SanitizeInput(string? input);
        
        /// <summary>
        /// Validates that input doesn't contain SQL injection patterns.
        /// </summary>
        bool ContainsSqlInjectionPatterns(string? input);
        
        /// <summary>
        /// Validates that input doesn't contain XSS patterns.
        /// </summary>
        bool ContainsXssPatterns(string? input);
        
        /// <summary>
        /// HTML encodes the input for safe display.
        /// </summary>
        string HtmlEncode(string? input);
        
        /// <summary>
        /// Validates email format strictly.
        /// </summary>
        bool IsValidEmail(string? email);
    }

    public class InputSanitizationService : IInputSanitizationService
    {
        // SQL injection patterns to detect
        private static readonly string[] SqlInjectionPatterns = new[]
        {
            @"(\s|^)(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|EXEC|UNION|DECLARE)(\s|$)",
            @"(--)|(;)",
            @"('|\x27)",  // Single quote
            @"(\""|\\x22)", // Double quote
            @"(\bOR\b|\bAND\b)\s*[\d\w]*\s*=\s*[\d\w]*",  // OR 1=1, AND 1=1
            @"(\/\*|\*\/)",  // SQL comments
            @"(xp_|sp_)",  // SQL Server stored procedures
        };

        // XSS patterns to detect
        private static readonly string[] XssPatterns = new[]
        {
            @"<script[^>]*>.*?</script>",
            @"<iframe[^>]*>.*?</iframe>",
            @"javascript:",
            @"vbscript:",
            @"onload\s*=",
            @"onerror\s*=",
            @"onclick\s*=",
            @"onmouseover\s*=",
            @"onfocus\s*=",
            @"onblur\s*=",
            @"<img[^>]*onerror[^>]*>",
            @"<svg[^>]*onload[^>]*>",
            @"expression\s*\(",
            @"url\s*\(\s*['""]?\s*data:",
        };

        public string SanitizeInput(string? input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            // Trim whitespace
            var sanitized = input.Trim();

            // Remove null bytes
            sanitized = sanitized.Replace("\0", "");

            // Remove control characters except newlines and tabs
            sanitized = Regex.Replace(sanitized, @"[\x00-\x08\x0B\x0C\x0E-\x1F]", "");

            return sanitized;
        }

        public bool ContainsSqlInjectionPatterns(string? input)
        {
            if (string.IsNullOrEmpty(input))
                return false;

            foreach (var pattern in SqlInjectionPatterns)
            {
                if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
                    return true;
            }

            return false;
        }

        public bool ContainsXssPatterns(string? input)
        {
            if (string.IsNullOrEmpty(input))
                return false;

            // Decode any HTML entities first to catch encoded attacks
            var decoded = HttpUtility.HtmlDecode(input);

            foreach (var pattern in XssPatterns)
            {
                if (Regex.IsMatch(decoded, pattern, RegexOptions.IgnoreCase | RegexOptions.Singleline))
                    return true;
            }

            return false;
        }

        public string HtmlEncode(string? input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            return HttpUtility.HtmlEncode(input);
        }

        public bool IsValidEmail(string? email)
        {
            if (string.IsNullOrEmpty(email))
                return false;

            // Strict email validation regex
            var emailPattern = @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$";
            return Regex.IsMatch(email, emailPattern);
        }
    }
}
