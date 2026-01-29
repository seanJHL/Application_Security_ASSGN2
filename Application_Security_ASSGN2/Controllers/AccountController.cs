using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Web;
using Application_Security_ASSGN2.Data;
using Application_Security_ASSGN2.Models;
using Application_Security_ASSGN2.Models.ViewModels;
using Application_Security_ASSGN2.Services;

namespace Application_Security_ASSGN2.Controllers
{
    public class AccountController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IPasswordService _passwordService;
        private readonly IEncryptionService _encryptionService;
        private readonly IReCaptchaService _reCaptchaService;
        private readonly IEmailService _emailService;
        private readonly IAuditLogService _auditLogService;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AccountController> _logger;
        private readonly IWebHostEnvironment _environment;

        public AccountController(
            ApplicationDbContext context,
            IPasswordService passwordService,
            IEncryptionService encryptionService,
            IReCaptchaService reCaptchaService,
            IEmailService emailService,
            IAuditLogService auditLogService,
            IConfiguration configuration,
            ILogger<AccountController> logger,
            IWebHostEnvironment environment)
        {
            _context = context;
            _passwordService = passwordService;
            _encryptionService = encryptionService;
            _reCaptchaService = reCaptchaService;
            _emailService = emailService;
            _auditLogService = auditLogService;
            _configuration = configuration;
            _logger = logger;
            _environment = environment;
        }

        private string? GetClientIpAddress()
        {
            return HttpContext.Connection.RemoteIpAddress?.ToString();
        }

        #region Register

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            // Verify reCAPTCHA
            if (!string.IsNullOrEmpty(model.RecaptchaToken))
            {
                var captchaValid = await _reCaptchaService.VerifyTokenAsync(model.RecaptchaToken);
                if (!captchaValid)
                {
                    ModelState.AddModelError("", "reCAPTCHA verification failed. Please try again.");
                    return View(model);
                }
            }

            // Validate password strength server-side
            var passwordErrors = _passwordService.ValidatePasswordStrength(model.Password);
            foreach (var error in passwordErrors)
            {
                ModelState.AddModelError("Password", error);
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // Check for duplicate email
            var existingUser = await _context.Members
                .FirstOrDefaultAsync(m => m.Email.ToLower() == model.Email.ToLower());

            if (existingUser != null)
            {
                ModelState.AddModelError("Email", "An account with this email already exists.");
                return View(model);
            }

            // Handle file upload
            string? resumePath = null;
            if (model.Resume != null && model.Resume.Length > 0)
            {
                var uploadsFolder = Path.Combine(_environment.WebRootPath, "uploads", "resumes");
                Directory.CreateDirectory(uploadsFolder);

                var extension = Path.GetExtension(model.Resume.FileName).ToLowerInvariant();
                var uniqueFileName = $"{Guid.NewGuid()}{extension}";
                var filePath = Path.Combine(uploadsFolder, uniqueFileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await model.Resume.CopyToAsync(stream);
                }

                resumePath = $"/uploads/resumes/{uniqueFileName}";
            }

            // Create member
            var member = new Member
            {
                FirstName = model.FirstName,
                LastName = model.LastName,
                Gender = model.Gender,
                NRIC = _encryptionService.Encrypt(model.NRIC.ToUpper()),
                Email = model.Email.ToLower(),
                PasswordHash = _passwordService.HashPassword(model.Password),
                DateOfBirth = model.DateOfBirth,
                ResumePath = resumePath,
                WhoAmI = !string.IsNullOrEmpty(model.WhoAmI) ? HttpUtility.HtmlEncode(model.WhoAmI) : null,
                PasswordChangedAt = DateTime.UtcNow
            };

            _context.Members.Add(member);
            await _context.SaveChangesAsync();

            // Add initial password to history
            await _passwordService.AddToPasswordHistoryAsync(member.Id, member.PasswordHash);

            // Log registration
            await _auditLogService.LogRegistrationAsync(member.Id, GetClientIpAddress());

            TempData["SuccessMessage"] = "Registration successful! Please login.";
            return RedirectToAction("Login");
        }

        #endregion

        #region Login

        [HttpGet]
        public IActionResult Login(string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;

            // Verify reCAPTCHA
            if (!string.IsNullOrEmpty(model.RecaptchaToken))
            {
                var captchaValid = await _reCaptchaService.VerifyTokenAsync(model.RecaptchaToken);
                if (!captchaValid)
                {
                    ModelState.AddModelError("", "reCAPTCHA verification failed. Please try again.");
                    return View(model);
                }
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var member = await _context.Members
                .FirstOrDefaultAsync(m => m.Email.ToLower() == model.Email.ToLower());

            if (member == null)
            {
                // Log failed attempt for non-existent user
                await _auditLogService.LogAsync(null, AuditAction.LoginFailed, GetClientIpAddress(), $"Email not found: {model.Email}");
                ModelState.AddModelError("", "Invalid email or password.");
                return View(model);
            }

            // Check if account is locked
            if (member.LockoutEnd.HasValue && member.LockoutEnd > DateTime.UtcNow)
            {
                var remainingMinutes = (int)Math.Ceiling((member.LockoutEnd.Value - DateTime.UtcNow).TotalMinutes);
                ModelState.AddModelError("", $"Account is locked. Please try again in {remainingMinutes} minute(s).");
                return View(model);
            }

            // Auto-recovery: Reset lockout if expired
            if (member.LockoutEnd.HasValue && member.LockoutEnd <= DateTime.UtcNow)
            {
                member.FailedLoginAttempts = 0;
                member.LockoutEnd = null;
                await _context.SaveChangesAsync();
            }

            // Verify password
            if (!_passwordService.VerifyPassword(model.Password, member.PasswordHash))
            {
                member.FailedLoginAttempts++;
                var maxAttempts = _configuration.GetValue<int>("PasswordPolicy:MaxFailedAttempts", 3);

                if (member.FailedLoginAttempts >= maxAttempts)
                {
                    var lockoutMinutes = _configuration.GetValue<int>("PasswordPolicy:LockoutDurationInMinutes", 15);
                    member.LockoutEnd = DateTime.UtcNow.AddMinutes(lockoutMinutes);
                    await _context.SaveChangesAsync();
                    
                    await _auditLogService.LogAccountLockedAsync(member.Id, GetClientIpAddress());
                    ModelState.AddModelError("", $"Account locked due to too many failed attempts. Please try again in {lockoutMinutes} minutes.");
                }
                else
                {
                    await _context.SaveChangesAsync();
                    var remainingAttempts = maxAttempts - member.FailedLoginAttempts;
                    await _auditLogService.LogLoginAsync(member.Id, GetClientIpAddress()!, false, $"Wrong password. Attempts remaining: {remainingAttempts}");
                    ModelState.AddModelError("", $"Invalid email or password. {remainingAttempts} attempt(s) remaining.");
                }

                return View(model);
            }

            // Check password age - force password change if expired
            var maxAgeDays = _configuration.GetValue<int>("PasswordPolicy:MaximumAgeInDays", 90);
            if ((DateTime.UtcNow - member.PasswordChangedAt).TotalDays > maxAgeDays)
            {
                TempData["WarningMessage"] = "Your password has expired. Please change it now.";
                HttpContext.Session.SetInt32("TempUserId", member.Id);
                return RedirectToAction("ChangePassword");
            }

            // Generate and send 2FA code
            var twoFactorCode = new Random().Next(100000, 999999).ToString();
            member.TwoFactorCode = twoFactorCode;
            member.TwoFactorCodeExpiry = DateTime.UtcNow.AddMinutes(5);
            await _context.SaveChangesAsync();

            try
            {
                await _emailService.Send2FACodeAsync(member.Email, twoFactorCode);
                await _auditLogService.LogAsync(member.Id, AuditAction.TwoFactorSent, GetClientIpAddress());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send 2FA code to {Email}", member.Email);
                // For development, log the code
                _logger.LogWarning("2FA Code for {Email}: {Code}", member.Email, twoFactorCode);
            }

            // Store email temporarily for 2FA verification
            HttpContext.Session.SetString("2FAEmail", member.Email);

            return RedirectToAction("Verify2FA");
        }

        #endregion

        #region Two-Factor Authentication

        [HttpGet]
        public IActionResult Verify2FA()
        {
            var email = HttpContext.Session.GetString("2FAEmail");
            if (string.IsNullOrEmpty(email))
            {
                return RedirectToAction("Login");
            }

            return View(new Verify2FAViewModel { Email = email });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Verify2FA(Verify2FAViewModel model)
        {
            var email = HttpContext.Session.GetString("2FAEmail");
            if (string.IsNullOrEmpty(email))
            {
                return RedirectToAction("Login");
            }

            if (!ModelState.IsValid)
            {
                model.Email = email;
                return View(model);
            }

            var member = await _context.Members
                .FirstOrDefaultAsync(m => m.Email.ToLower() == email.ToLower());

            if (member == null)
            {
                return RedirectToAction("Login");
            }

            // Verify code
            if (member.TwoFactorCode != model.Code || member.TwoFactorCodeExpiry < DateTime.UtcNow)
            {
                await _auditLogService.Log2FAAsync(member.Id, GetClientIpAddress(), false);
                ModelState.AddModelError("Code", "Invalid or expired verification code.");
                model.Email = email;
                return View(model);
            }

            // Clear 2FA code
            member.TwoFactorCode = null;
            member.TwoFactorCodeExpiry = null;

            // Reset failed login attempts
            member.FailedLoginAttempts = 0;
            member.LockoutEnd = null;

            // Generate session token
            var sessionToken = Guid.NewGuid().ToString();
            member.SessionToken = sessionToken;
            await _context.SaveChangesAsync();

            // Set session
            HttpContext.Session.SetInt32("UserId", member.Id);
            HttpContext.Session.SetString("SessionToken", sessionToken);
            HttpContext.Session.SetString("UserEmail", member.Email);
            HttpContext.Session.SetString("UserName", $"{member.FirstName} {member.LastName}");
            HttpContext.Session.Remove("2FAEmail");

            await _auditLogService.Log2FAAsync(member.Id, GetClientIpAddress(), true);
            await _auditLogService.LogLoginAsync(member.Id, GetClientIpAddress()!, true);

            // Redirect to home page
            return Redirect("/");
        }

        #endregion

        #region Logout

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var userId = HttpContext.Session.GetInt32("UserId");

            if (userId.HasValue)
            {
                var member = await _context.Members.FindAsync(userId.Value);
                if (member != null)
                {
                    member.SessionToken = null;
                    await _context.SaveChangesAsync();
                }

                await _auditLogService.LogLogoutAsync(userId.Value, GetClientIpAddress());
            }

            HttpContext.Session.Clear();

            return RedirectToAction("Login");
        }

        #endregion

        #region Change Password

        [HttpGet]
        public IActionResult ChangePassword()
        {
            var userId = HttpContext.Session.GetInt32("UserId") ?? HttpContext.Session.GetInt32("TempUserId");
            if (!userId.HasValue)
            {
                return RedirectToAction("Login");
            }

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            var userId = HttpContext.Session.GetInt32("UserId") ?? HttpContext.Session.GetInt32("TempUserId");
            if (!userId.HasValue)
            {
                return RedirectToAction("Login");
            }

            // Validate new password strength
            var passwordErrors = _passwordService.ValidatePasswordStrength(model.NewPassword);
            foreach (var error in passwordErrors)
            {
                ModelState.AddModelError("NewPassword", error);
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var member = await _context.Members.FindAsync(userId.Value);
            if (member == null)
            {
                return RedirectToAction("Login");
            }

            // Verify current password
            if (!_passwordService.VerifyPassword(model.CurrentPassword, member.PasswordHash))
            {
                ModelState.AddModelError("CurrentPassword", "Current password is incorrect.");
                return View(model);
            }

            // Check minimum password age
            var minAgeMinutes = _configuration.GetValue<int>("PasswordPolicy:MinimumAgeInMinutes", 1);
            if ((DateTime.UtcNow - member.PasswordChangedAt).TotalMinutes < minAgeMinutes)
            {
                ModelState.AddModelError("", $"You must wait at least {minAgeMinutes} minute(s) before changing your password again.");
                return View(model);
            }

            // Check password history
            if (await _passwordService.IsPasswordInHistoryAsync(userId.Value, model.NewPassword))
            {
                ModelState.AddModelError("NewPassword", "You cannot reuse any of your last 2 passwords.");
                return View(model);
            }

            // Update password
            member.PasswordHash = _passwordService.HashPassword(model.NewPassword);
            member.PasswordChangedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();

            // Add to password history
            await _passwordService.AddToPasswordHistoryAsync(member.Id, member.PasswordHash);

            await _auditLogService.LogPasswordChangeAsync(member.Id, GetClientIpAddress());

            // Clear temp user ID if it was a forced password change
            HttpContext.Session.Remove("TempUserId");

            TempData["SuccessMessage"] = "Password changed successfully!";

            // If user was logged in, redirect to home; otherwise, to login
            if (HttpContext.Session.GetInt32("UserId").HasValue)
            {
                return Redirect("/");
            }

            return RedirectToAction("Login");
        }

        #endregion

        #region Forgot Password

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            // Verify reCAPTCHA
            if (!string.IsNullOrEmpty(model.RecaptchaToken))
            {
                var captchaValid = await _reCaptchaService.VerifyTokenAsync(model.RecaptchaToken);
                if (!captchaValid)
                {
                    ModelState.AddModelError("", "reCAPTCHA verification failed. Please try again.");
                    return View(model);
                }
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // Always show success message to prevent email enumeration
            TempData["SuccessMessage"] = "If an account exists with this email, you will receive a password reset link shortly.";

            var member = await _context.Members
                .FirstOrDefaultAsync(m => m.Email.ToLower() == model.Email.ToLower());

            if (member != null)
            {
                // Generate reset token
                var token = Guid.NewGuid().ToString();
                var resetToken = new PasswordResetToken
                {
                    MemberId = member.Id,
                    Token = token,
                    ExpiresAt = DateTime.UtcNow.AddHours(1),
                    Used = false
                };

                _context.PasswordResetTokens.Add(resetToken);
                await _context.SaveChangesAsync();

                // Send reset email
                var resetLink = Url.Action("ResetPassword", "Account", new { token }, Request.Scheme);
                try
                {
                    await _emailService.SendPasswordResetLinkAsync(member.Email, resetLink!);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to send password reset email to {Email}", member.Email);
                    // For development, log the link
                    _logger.LogWarning("Password reset link for {Email}: {Link}", member.Email, resetLink);
                }
            }

            return RedirectToAction("ForgotPassword");
        }

        #endregion

        #region Reset Password

        [HttpGet]
        public async Task<IActionResult> ResetPassword(string? token)
        {
            if (string.IsNullOrEmpty(token))
            {
                return RedirectToAction("Login");
            }

            var resetToken = await _context.PasswordResetTokens
                .FirstOrDefaultAsync(t => t.Token == token && !t.Used && t.ExpiresAt > DateTime.UtcNow);

            if (resetToken == null)
            {
                TempData["ErrorMessage"] = "Invalid or expired password reset link.";
                return RedirectToAction("Login");
            }

            return View(new ResetPasswordViewModel { Token = token });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            // Validate password strength
            var passwordErrors = _passwordService.ValidatePasswordStrength(model.NewPassword);
            foreach (var error in passwordErrors)
            {
                ModelState.AddModelError("NewPassword", error);
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var resetToken = await _context.PasswordResetTokens
                .Include(t => t.Member)
                .FirstOrDefaultAsync(t => t.Token == model.Token && !t.Used && t.ExpiresAt > DateTime.UtcNow);

            if (resetToken == null)
            {
                TempData["ErrorMessage"] = "Invalid or expired password reset link.";
                return RedirectToAction("Login");
            }

            var member = resetToken.Member;

            // Check password history
            if (await _passwordService.IsPasswordInHistoryAsync(member.Id, model.NewPassword))
            {
                ModelState.AddModelError("NewPassword", "You cannot reuse any of your last 2 passwords.");
                return View(model);
            }

            // Update password
            member.PasswordHash = _passwordService.HashPassword(model.NewPassword);
            member.PasswordChangedAt = DateTime.UtcNow;
            member.FailedLoginAttempts = 0;
            member.LockoutEnd = null;

            // Mark token as used
            resetToken.Used = true;

            await _context.SaveChangesAsync();

            // Add to password history
            await _passwordService.AddToPasswordHistoryAsync(member.Id, member.PasswordHash);

            await _auditLogService.LogPasswordResetAsync(member.Id, GetClientIpAddress());

            TempData["SuccessMessage"] = "Password reset successfully! Please login with your new password.";
            return RedirectToAction("Login");
        }

        #endregion

        #region Access Denied

        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }

        #endregion
    }
}
