using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Application_Security_ASSGN2.Models
{
    public class AuditLog
    {
        [Key]
        public int Id { get; set; }

        public int? UserId { get; set; }

        [Required]
        [StringLength(50)]
        public string Action { get; set; } = string.Empty;

        [Required]
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        [StringLength(45)] // IPv6 max length
        public string? IpAddress { get; set; }

        [StringLength(500)]
        public string? Details { get; set; }

        // Navigation property
        [ForeignKey("UserId")]
        public virtual Member? User { get; set; }
    }

    public static class AuditAction
    {
        public const string Login = "Login";
        public const string LoginFailed = "LoginFailed";
        public const string Logout = "Logout";
        public const string Register = "Register";
        public const string PasswordChange = "PasswordChange";
        public const string PasswordReset = "PasswordReset";
        public const string AccountLocked = "AccountLocked";
        public const string TwoFactorSent = "TwoFactorSent";
        public const string TwoFactorVerified = "TwoFactorVerified";
        public const string TwoFactorFailed = "TwoFactorFailed";
    }
}
