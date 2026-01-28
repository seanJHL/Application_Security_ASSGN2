using Application_Security_ASSGN2.Data;
using Application_Security_ASSGN2.Models;

namespace Application_Security_ASSGN2.Services
{
    public interface IAuditLogService
    {
        Task LogAsync(int? userId, string action, string? ipAddress, string? details = null);
        Task LogLoginAsync(int userId, string ipAddress, bool success, string? details = null);
        Task LogLogoutAsync(int userId, string? ipAddress);
        Task LogRegistrationAsync(int userId, string? ipAddress);
        Task LogPasswordChangeAsync(int userId, string? ipAddress);
        Task LogPasswordResetAsync(int userId, string? ipAddress);
        Task LogAccountLockedAsync(int userId, string? ipAddress);
        Task Log2FAAsync(int userId, string? ipAddress, bool success);
    }

    public class AuditLogService : IAuditLogService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<AuditLogService> _logger;

        public AuditLogService(ApplicationDbContext context, ILogger<AuditLogService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task LogAsync(int? userId, string action, string? ipAddress, string? details = null)
        {
            try
            {
                var auditLog = new AuditLog
                {
                    UserId = userId,
                    Action = action,
                    Timestamp = DateTime.UtcNow,
                    IpAddress = ipAddress,
                    Details = details?.Length > 500 ? details.Substring(0, 500) : details
                };

                _context.AuditLogs.Add(auditLog);
                await _context.SaveChangesAsync();

                _logger.LogInformation("Audit log: {Action} for user {UserId} from {IpAddress}", action, userId, ipAddress);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create audit log for action {Action}", action);
            }
        }

        public async Task LogLoginAsync(int userId, string ipAddress, bool success, string? details = null)
        {
            await LogAsync(userId, success ? AuditAction.Login : AuditAction.LoginFailed, ipAddress, details);
        }

        public async Task LogLogoutAsync(int userId, string? ipAddress)
        {
            await LogAsync(userId, AuditAction.Logout, ipAddress);
        }

        public async Task LogRegistrationAsync(int userId, string? ipAddress)
        {
            await LogAsync(userId, AuditAction.Register, ipAddress);
        }

        public async Task LogPasswordChangeAsync(int userId, string? ipAddress)
        {
            await LogAsync(userId, AuditAction.PasswordChange, ipAddress);
        }

        public async Task LogPasswordResetAsync(int userId, string? ipAddress)
        {
            await LogAsync(userId, AuditAction.PasswordReset, ipAddress);
        }

        public async Task LogAccountLockedAsync(int userId, string? ipAddress)
        {
            await LogAsync(userId, AuditAction.AccountLocked, ipAddress);
        }

        public async Task Log2FAAsync(int userId, string? ipAddress, bool success)
        {
            await LogAsync(userId, success ? AuditAction.TwoFactorVerified : AuditAction.TwoFactorFailed, ipAddress);
        }
    }
}
