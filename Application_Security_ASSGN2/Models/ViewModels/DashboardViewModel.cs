using System.ComponentModel.DataAnnotations;

namespace Application_Security_ASSGN2.Models.ViewModels
{
    public class DashboardViewModel
    {
        // User Information
        public Member Member { get; set; } = null!;
        public string DecryptedNRIC { get; set; } = string.Empty;
        
        // Profile Update Form
        public UpdateProfileViewModel ProfileForm { get; set; } = new();

        // Account Policy Settings (from configuration)
        public int LockoutDurationInMinutes { get; set; }
        public int MaxFailedAttempts { get; set; }
        public int PasswordHistoryCount { get; set; }
        public int MinimumPasswordAgeInMinutes { get; set; }
        public int MaximumPasswordAgeInDays { get; set; }
        public int SessionTimeoutInMinutes { get; set; }

        // Password Status
        public DateTime PasswordChangedAt { get; set; }
        public int DaysUntilPasswordExpiry { get; set; }
        public bool CanChangePassword { get; set; }
        public int MinutesUntilCanChangePassword { get; set; }

        // Account Status
        public bool IsLocked { get; set; }
        public int? MinutesUntilUnlock { get; set; }
        public int FailedLoginAttempts { get; set; }
    }
}
