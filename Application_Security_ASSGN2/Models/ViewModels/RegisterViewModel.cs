using System.ComponentModel.DataAnnotations;
using Application_Security_ASSGN2.Validation;
using Microsoft.AspNetCore.Http;

namespace Application_Security_ASSGN2.Models.ViewModels
{
    public class RegisterViewModel
    {
        [Required(ErrorMessage = "First name is required")]
        [StringLength(50, ErrorMessage = "First name cannot exceed 50 characters")]
        [Display(Name = "First Name")]
        public string FirstName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Last name is required")]
        [StringLength(50, ErrorMessage = "Last name cannot exceed 50 characters")]
        [Display(Name = "Last Name")]
        public string LastName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Gender is required")]
        [Display(Name = "Gender")]
        public string Gender { get; set; } = string.Empty;

        [Required(ErrorMessage = "NRIC is required")]
        [Nric(ErrorMessage = "Invalid NRIC format. Must be in format: S1234567A")]
        [Display(Name = "NRIC")]
        public string NRIC { get; set; } = string.Empty;

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        [StringLength(100)]
        [Display(Name = "Email")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required")]
        [StringLength(100, MinimumLength = 12, ErrorMessage = "Password must be at least 12 characters")]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage = "Confirm password is required")]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm Password")]
        [Compare("Password", ErrorMessage = "Passwords do not match")]
        public string ConfirmPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "Date of birth is required")]
        [DataType(DataType.Date)]
        [Display(Name = "Date of Birth")]
        public DateTime DateOfBirth { get; set; }

        [Display(Name = "Resume (PDF or DOCX only)")]
        [AllowedExtensions(new string[] { ".pdf", ".docx" }, ErrorMessage = "Only PDF and DOCX files are allowed")]
        public IFormFile? Resume { get; set; }

        [StringLength(500, ErrorMessage = "Who Am I cannot exceed 500 characters")]
        [Display(Name = "Who Am I")]
        public string? WhoAmI { get; set; }

        // reCAPTCHA token
        public string? RecaptchaToken { get; set; }
    }
}
