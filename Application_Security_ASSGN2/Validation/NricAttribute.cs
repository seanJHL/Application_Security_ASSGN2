using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace Application_Security_ASSGN2.Validation
{
    /// <summary>
    /// Validates Singapore NRIC format: S/T/F/G followed by 7 digits and an uppercase letter
    /// Example: S1234567A
    /// </summary>
    public class NricAttribute : ValidationAttribute
    {
        private const string NricPattern = @"^[STFG]\d{7}[A-Z]$";

        protected override ValidationResult? IsValid(object? value, ValidationContext validationContext)
        {
            if (value == null || string.IsNullOrWhiteSpace(value.ToString()))
            {
                // Required attribute should handle null/empty check
                return ValidationResult.Success;
            }

            string nric = value.ToString()!.ToUpper();

            if (!Regex.IsMatch(nric, NricPattern))
            {
                return new ValidationResult(ErrorMessage ?? "Invalid NRIC format. Must be in format: S1234567A");
            }

            return ValidationResult.Success;
        }
    }
}
