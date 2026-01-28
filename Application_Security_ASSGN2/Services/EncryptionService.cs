using System.Security.Cryptography;
using System.Text;

namespace Application_Security_ASSGN2.Services
{
    public interface IEncryptionService
    {
        string Encrypt(string plainText);
        string Decrypt(string cipherText);
    }

    public class EncryptionService : IEncryptionService
    {
        private readonly byte[] _key;
        private readonly byte[] _iv;

        public EncryptionService(IConfiguration configuration)
        {
            var keyString = configuration["EncryptionSettings:Key"] 
                ?? throw new InvalidOperationException("Encryption key not configured");
            
            // Ensure key is exactly 32 bytes for AES-256
            _key = new byte[32];
            var keyBytes = Encoding.UTF8.GetBytes(keyString);
            Array.Copy(keyBytes, _key, Math.Min(keyBytes.Length, 32));
            
            // Use a fixed IV derived from the key (in production, consider storing IV with ciphertext)
            using (var sha256 = SHA256.Create())
            {
                var hash = sha256.ComputeHash(_key);
                _iv = new byte[16];
                Array.Copy(hash, _iv, 16);
            }
        }

        public string Encrypt(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
                return plainText;

            using var aes = Aes.Create();
            aes.Key = _key;
            aes.IV = _iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var encryptor = aes.CreateEncryptor();
            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            var cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
            
            return Convert.ToBase64String(cipherBytes);
        }

        public string Decrypt(string cipherText)
        {
            if (string.IsNullOrEmpty(cipherText))
                return cipherText;

            try
            {
                using var aes = Aes.Create();
                aes.Key = _key;
                aes.IV = _iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using var decryptor = aes.CreateDecryptor();
                var cipherBytes = Convert.FromBase64String(cipherText);
                var plainBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
                
                return Encoding.UTF8.GetString(plainBytes);
            }
            catch (Exception)
            {
                // Return original if decryption fails (might not be encrypted)
                return cipherText;
            }
        }
    }
}
