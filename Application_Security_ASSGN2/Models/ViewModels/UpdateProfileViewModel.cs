using System.ComponentModel.DataAnnotations;
using Application_Security_ASSGN2.Validation;

namespace Application_Security_ASSGN2.Models.ViewModels
{
    public class UpdateProfileViewModel
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
        [Nric(ErrorMessage = "Please enter a valid NRIC (e.g., S1234567A)")]
        [Display(Name = "NRIC")]
        public string NRIC { get; set; } = string.Empty;

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Please enter a valid email address")]
        [StringLength(100, ErrorMessage = "Email cannot exceed 100 characters")]
        [Display(Name = "Email Address")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Date of birth is required")]
        [DataType(DataType.Date)]
        [Display(Name = "Date of Birth")]
        public DateTime DateOfBirth { get; set; }

        [Display(Name = "Resume")]
        [AllowedExtensions(new string[] { ".pdf", ".docx" }, ErrorMessage = "Only .pdf and .docx files are allowed")]
        public IFormFile? Resume { get; set; }

        [StringLength(500, ErrorMessage = "Who Am I cannot exceed 500 characters")]
        [Display(Name = "Who Am I")]
        public string? WhoAmI { get; set; }

        // For display purposes
        public string? CurrentResumePath { get; set; }
    }
}
