using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Http;

namespace Application_Security_ASSGN2.Validation
{
    /// <summary>
    /// Validates that uploaded files have allowed extensions
    /// </summary>
    public class AllowedExtensionsAttribute : ValidationAttribute
    {
        private readonly string[] _extensions;

        public AllowedExtensionsAttribute(string[] extensions)
        {
            _extensions = extensions;
        }

        protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
        {
            if (value is IFormFile file)
            {
                var extension = Path.GetExtension(file.FileName).ToLowerInvariant();

                if (!_extensions.Contains(extension))
                {
                    return new ValidationResult(ErrorMessage ?? $"Only {string.Join(", ", _extensions)} files are allowed.");
                }

                // Also validate content type for additional security
                var allowedContentTypes = new Dictionary<string, string[]>
                {
                    { ".pdf", new[] { "application/pdf" } },
                    { ".docx", new[] { "application/vnd.openxmlformats-officedocument.wordprocessingml.document" } }
                };

                if (allowedContentTypes.TryGetValue(extension, out var validContentTypes))
                {
                    if (!validContentTypes.Contains(file.ContentType.ToLowerInvariant()))
                    {
                        return new ValidationResult("File content type does not match the file extension.");
                    }
                }
            }

            return ValidationResult.Success;
        }
    }
}
