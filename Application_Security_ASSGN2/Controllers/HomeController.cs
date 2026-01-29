using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Web;
using Application_Security_ASSGN2.Data;
using Application_Security_ASSGN2.Models.ViewModels;
using Application_Security_ASSGN2.Services;

namespace Application_Security_ASSGN2.Controllers
{
    public class HomeController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IEncryptionService _encryptionService;
        private readonly IConfiguration _configuration;
        private readonly IWebHostEnvironment _environment;
        private readonly IAuditLogService _auditLogService;

        public HomeController(
            ApplicationDbContext context, 
            IEncryptionService encryptionService,
            IConfiguration configuration,
            IWebHostEnvironment environment,
            IAuditLogService auditLogService)
        {
            _context = context;
            _encryptionService = encryptionService;
            _configuration = configuration;
            _environment = environment;
            _auditLogService = auditLogService;
        }

        private string? GetClientIpAddress()
        {
            return HttpContext.Connection.RemoteIpAddress?.ToString();
        }

        public async Task<IActionResult> Index()
        {
            var userId = HttpContext.Session.GetInt32("UserId");

            if (!userId.HasValue)
            {
                return RedirectToAction("Login", "Account");
            }

            var member = await _context.Members.FindAsync(userId.Value);

            if (member == null)
            {
                HttpContext.Session.Clear();
                return RedirectToAction("Login", "Account");
            }

            var decryptedNRIC = _encryptionService.Decrypt(member.NRIC);

            // Get configuration values
            var lockoutDuration = _configuration.GetValue<int>("PasswordPolicy:LockoutDurationInMinutes", 15);
            var maxFailedAttempts = _configuration.GetValue<int>("PasswordPolicy:MaxFailedAttempts", 3);
            var minAgeMinutes = _configuration.GetValue<int>("PasswordPolicy:MinimumAgeInMinutes", 1);
            var maxAgeDays = _configuration.GetValue<int>("PasswordPolicy:MaximumAgeInDays", 90);
            var sessionTimeout = _configuration.GetValue<int>("SessionSettings:TimeoutInMinutes", 30);

            // Calculate password status
            var daysSincePasswordChange = (DateTime.UtcNow - member.PasswordChangedAt).TotalDays;
            var daysUntilExpiry = maxAgeDays - (int)daysSincePasswordChange;
            
            var minutesSincePasswordChange = (DateTime.UtcNow - member.PasswordChangedAt).TotalMinutes;
            var canChangePassword = minutesSincePasswordChange >= minAgeMinutes;
            var minutesUntilCanChange = canChangePassword ? 0 : (int)Math.Ceiling(minAgeMinutes - minutesSincePasswordChange);

            // Check lockout status
            var isLocked = member.LockoutEnd.HasValue && member.LockoutEnd > DateTime.UtcNow;
            var minutesUntilUnlock = isLocked 
                ? (int)Math.Ceiling((member.LockoutEnd!.Value - DateTime.UtcNow).TotalMinutes) 
                : (int?)null;

            var viewModel = new DashboardViewModel
            {
                Member = member,
                DecryptedNRIC = decryptedNRIC,
                
                // Profile Form - populate with current values
                ProfileForm = new UpdateProfileViewModel
                {
                    FirstName = member.FirstName,
                    LastName = member.LastName,
                    Gender = member.Gender,
                    NRIC = decryptedNRIC,
                    Email = member.Email,
                    DateOfBirth = member.DateOfBirth,
                    WhoAmI = member.WhoAmI != null ? HttpUtility.HtmlDecode(member.WhoAmI) : null,
                    CurrentResumePath = member.ResumePath
                },
                
                // Policy Settings
                LockoutDurationInMinutes = lockoutDuration,
                MaxFailedAttempts = maxFailedAttempts,
                PasswordHistoryCount = 2, // Hardcoded as per requirement
                MinimumPasswordAgeInMinutes = minAgeMinutes,
                MaximumPasswordAgeInDays = maxAgeDays,
                SessionTimeoutInMinutes = sessionTimeout,
                
                // Password Status
                PasswordChangedAt = member.PasswordChangedAt,
                DaysUntilPasswordExpiry = daysUntilExpiry,
                CanChangePassword = canChangePassword,
                MinutesUntilCanChangePassword = minutesUntilCanChange,
                
                // Account Status
                IsLocked = isLocked,
                MinutesUntilUnlock = minutesUntilUnlock,
                FailedLoginAttempts = member.FailedLoginAttempts
            };

            return View(viewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UpdateProfile(UpdateProfileViewModel model)
        {
            var userId = HttpContext.Session.GetInt32("UserId");

            if (!userId.HasValue)
            {
                return RedirectToAction("Login", "Account");
            }

            var member = await _context.Members.FindAsync(userId.Value);

            if (member == null)
            {
                HttpContext.Session.Clear();
                return RedirectToAction("Login", "Account");
            }

            if (!ModelState.IsValid)
            {
                TempData["ErrorMessage"] = "Please correct the errors in the form.";
                return RedirectToAction("Index");
            }

            // Check if email is being changed and if it's unique
            var normalizedEmail = model.Email.ToLower();
            if (normalizedEmail != member.Email.ToLower())
            {
                var existingUser = await _context.Members
                    .FirstOrDefaultAsync(m => m.Email.ToLower() == normalizedEmail && m.Id != userId);

                if (existingUser != null)
                {
                    TempData["ErrorMessage"] = "An account with this email already exists.";
                    return RedirectToAction("Index");
                }
            }

            // Handle file upload
            if (model.Resume != null && model.Resume.Length > 0)
            {
                // Delete old resume if exists
                if (!string.IsNullOrEmpty(member.ResumePath))
                {
                    var oldFilePath = Path.Combine(_environment.WebRootPath, member.ResumePath.TrimStart('/'));
                    if (System.IO.File.Exists(oldFilePath))
                    {
                        System.IO.File.Delete(oldFilePath);
                    }
                }

                var uploadsFolder = Path.Combine(_environment.WebRootPath, "uploads", "resumes");
                Directory.CreateDirectory(uploadsFolder);

                var extension = Path.GetExtension(model.Resume.FileName).ToLowerInvariant();
                var uniqueFileName = $"{Guid.NewGuid()}{extension}";
                var filePath = Path.Combine(uploadsFolder, uniqueFileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await model.Resume.CopyToAsync(stream);
                }

                member.ResumePath = $"/uploads/resumes/{uniqueFileName}";
            }

            // Update member fields
            member.FirstName = model.FirstName;
            member.LastName = model.LastName;
            member.Gender = model.Gender;
            member.NRIC = _encryptionService.Encrypt(model.NRIC.ToUpper());
            member.Email = normalizedEmail;
            member.DateOfBirth = model.DateOfBirth;
            member.WhoAmI = !string.IsNullOrEmpty(model.WhoAmI) ? HttpUtility.HtmlEncode(model.WhoAmI) : null;

            await _context.SaveChangesAsync();

            // Update session with new name
            HttpContext.Session.SetString("UserName", $"{member.FirstName} {member.LastName}");
            HttpContext.Session.SetString("UserEmail", member.Email);

            // Log the profile update
            await _auditLogService.LogAsync(member.Id, "ProfileUpdate", GetClientIpAddress(), "User updated their profile");

            TempData["SuccessMessage"] = "Profile updated successfully!";
            return RedirectToAction("Index");
        }

        public IActionResult Privacy()
        {
            return View();
        }
    }
}
