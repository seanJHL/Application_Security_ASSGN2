using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Konscious.Security.Cryptography;
using Application_Security_ASSGN2.Data;
using Application_Security_ASSGN2.Models;
using Microsoft.EntityFrameworkCore;

namespace Application_Security_ASSGN2.Services
{
    public interface IPasswordService
    {
        string HashPassword(string password);
        bool VerifyPassword(string password, string hash);
        List<string> ValidatePasswordStrength(string password);
        Task<bool> IsPasswordInHistoryAsync(int memberId, string password, int historyCount = 2);
        Task AddToPasswordHistoryAsync(int memberId, string passwordHash);
    }

    public class PasswordService : IPasswordService
    {
        private readonly ApplicationDbContext _context;
        private const int DegreeOfParallelism = 4;
        private const int MemorySize = 65536; // 64 MB
        private const int Iterations = 4;

        public PasswordService(ApplicationDbContext context)
        {
            _context = context;
        }

        /// <summary>
        /// Hash password using Argon2id
        /// </summary>
        public string HashPassword(string password)
        {
            // Generate a random salt
            var salt = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
            {
                Salt = salt,
                DegreeOfParallelism = DegreeOfParallelism,
                MemorySize = MemorySize,
                Iterations = Iterations
            };

            var hash = argon2.GetBytes(32);

            // Format: $argon2id$v=19$m=65536,t=4,p=4$<salt>$<hash>
            var saltBase64 = Convert.ToBase64String(salt);
            var hashBase64 = Convert.ToBase64String(hash);

            return $"$argon2id$v=19$m={MemorySize},t={Iterations},p={DegreeOfParallelism}${saltBase64}${hashBase64}";
        }

        /// <summary>
        /// Verify password against Argon2id hash
        /// </summary>
        public bool VerifyPassword(string password, string hash)
        {
            try
            {
                // Parse the stored hash
                var parts = hash.Split('$');
                if (parts.Length != 6 || parts[1] != "argon2id")
                    return false;

                // Parse parameters
                var paramParts = parts[3].Split(',');
                var memorySize = int.Parse(paramParts[0].Split('=')[1]);
                var iterations = int.Parse(paramParts[1].Split('=')[1]);
                var parallelism = int.Parse(paramParts[2].Split('=')[1]);

                var salt = Convert.FromBase64String(parts[4]);
                var storedHash = Convert.FromBase64String(parts[5]);

                var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
                {
                    Salt = salt,
                    DegreeOfParallelism = parallelism,
                    MemorySize = memorySize,
                    Iterations = iterations
                };

                var computedHash = argon2.GetBytes(32);

                // Constant-time comparison
                return CryptographicOperations.FixedTimeEquals(computedHash, storedHash);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Validate password strength and return list of failed requirements
        /// </summary>
        public List<string> ValidatePasswordStrength(string password)
        {
            var errors = new List<string>();

            if (string.IsNullOrEmpty(password))
            {
                errors.Add("Password is required");
                return errors;
            }

            if (password.Length < 12)
                errors.Add("Password must be at least 12 characters long");

            if (!Regex.IsMatch(password, @"[a-z]"))
                errors.Add("Password must contain at least one lowercase letter");

            if (!Regex.IsMatch(password, @"[A-Z]"))
                errors.Add("Password must contain at least one uppercase letter");

            if (!Regex.IsMatch(password, @"[0-9]"))
                errors.Add("Password must contain at least one number");

            if (!Regex.IsMatch(password, @"[!@#$%^&*(),.?""':{}|<>]"))
                errors.Add("Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)");

            return errors;
        }

        /// <summary>
        /// Check if password was used in the last N password changes
        /// </summary>
        public async Task<bool> IsPasswordInHistoryAsync(int memberId, string password, int historyCount = 2)
        {
            var recentPasswords = await _context.PasswordHistories
                .Where(ph => ph.MemberId == memberId)
                .OrderByDescending(ph => ph.CreatedAt)
                .Take(historyCount)
                .Select(ph => ph.PasswordHash)
                .ToListAsync();

            foreach (var historicalHash in recentPasswords)
            {
                if (VerifyPassword(password, historicalHash))
                    return true;
            }

            return false;
        }

        /// <summary>
        /// Add password to history and maintain only the last N entries
        /// </summary>
        public async Task AddToPasswordHistoryAsync(int memberId, string passwordHash)
        {
            // Add new entry
            _context.PasswordHistories.Add(new PasswordHistory
            {
                MemberId = memberId,
                PasswordHash = passwordHash,
                CreatedAt = DateTime.UtcNow
            });

            // Keep only the last 2 passwords
            var oldEntries = await _context.PasswordHistories
                .Where(ph => ph.MemberId == memberId)
                .OrderByDescending(ph => ph.CreatedAt)
                .Skip(2)
                .ToListAsync();

            _context.PasswordHistories.RemoveRange(oldEntries);

            await _context.SaveChangesAsync();
        }
    }
}
