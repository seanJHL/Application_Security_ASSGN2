using System.ComponentModel.DataAnnotations;

namespace Application_Security_ASSGN2.Models.ViewModels
{
    public class Verify2FAViewModel
    {
        [Required(ErrorMessage = "Verification code is required")]
        [StringLength(6, MinimumLength = 6, ErrorMessage = "Code must be 6 digits")]
        [RegularExpression(@"^\d{6}$", ErrorMessage = "Code must be 6 digits")]
        [Display(Name = "Verification Code")]
        public string Code { get; set; } = string.Empty;

        public string? Email { get; set; }
    }
}
