using System.ComponentModel.DataAnnotations;

namespace Application_Security_ASSGN2.Models.ViewModels
{
    public class ForgotPasswordViewModel
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        [Display(Name = "Email")]
        public string Email { get; set; } = string.Empty;

        // reCAPTCHA token
        public string? RecaptchaToken { get; set; }
    }
}
