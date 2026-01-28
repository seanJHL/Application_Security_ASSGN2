using System.Text;
using Newtonsoft.Json;

namespace Application_Security_ASSGN2.Services
{
    public interface IEmailService
    {
        Task SendEmailAsync(string toEmail, string subject, string htmlBody);
        Task Send2FACodeAsync(string toEmail, string code);
        Task SendPasswordResetLinkAsync(string toEmail, string resetLink);
    }

    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<EmailService> _logger;
        private readonly HttpClient _httpClient;
        private const string ResendApiUrl = "https://api.resend.com/emails";

        public EmailService(IConfiguration configuration, ILogger<EmailService> logger, IHttpClientFactory httpClientFactory)
        {
            _configuration = configuration;
            _logger = logger;
            _httpClient = httpClientFactory.CreateClient();
        }

        public async Task SendEmailAsync(string toEmail, string subject, string htmlBody)
        {
            try
            {
                var resendSettings = _configuration.GetSection("ResendSettings");
                var apiKey = resendSettings["ApiKey"];
                var senderName = resendSettings["SenderName"] ?? "Application Security";
                var senderEmail = resendSettings["SenderEmail"] ?? "onboarding@resend.dev";

                if (string.IsNullOrEmpty(apiKey) || apiKey == "YOUR_RESEND_API_KEY")
                {
                    _logger.LogWarning("Resend API key not configured. Email not sent to {Email}. Subject: {Subject}", toEmail, subject);
                    return;
                }

                var emailData = new
                {
                    from = $"{senderName} <{senderEmail}>",
                    to = new[] { toEmail },
                    subject = subject,
                    html = htmlBody
                };

                var json = JsonConvert.SerializeObject(emailData);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                _httpClient.DefaultRequestHeaders.Clear();
                _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {apiKey}");

                var response = await _httpClient.PostAsync(ResendApiUrl, content);
                var responseContent = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation("Email sent successfully to {Email} via Resend", toEmail);
                }
                else
                {
                    _logger.LogError("Failed to send email via Resend. Status: {StatusCode}, Response: {Response}", 
                        response.StatusCode, responseContent);
                    throw new Exception($"Failed to send email: {responseContent}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send email to {Email}", toEmail);
                throw;
            }
        }

        public async Task Send2FACodeAsync(string toEmail, string code)
        {
            var subject = "Your Two-Factor Authentication Code";
            var htmlBody = $@"
                <html>
                <body style='font-family: Arial, sans-serif;'>
                    <div style='max-width: 600px; margin: 0 auto; padding: 20px;'>
                        <h2 style='color: #333;'>Two-Factor Authentication</h2>
                        <p>Your verification code is:</p>
                        <div style='background-color: #f4f4f4; padding: 20px; text-align: center; margin: 20px 0;'>
                            <span style='font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #007bff;'>{code}</span>
                        </div>
                        <p>This code will expire in 5 minutes.</p>
                        <p style='color: #666; font-size: 12px;'>If you did not request this code, please ignore this email.</p>
                    </div>
                </body>
                </html>";

            await SendEmailAsync(toEmail, subject, htmlBody);
        }

        public async Task SendPasswordResetLinkAsync(string toEmail, string resetLink)
        {
            var subject = "Password Reset Request";
            var htmlBody = $@"
                <html>
                <body style='font-family: Arial, sans-serif;'>
                    <div style='max-width: 600px; margin: 0 auto; padding: 20px;'>
                        <h2 style='color: #333;'>Password Reset Request</h2>
                        <p>We received a request to reset your password. Click the button below to set a new password:</p>
                        <div style='text-align: center; margin: 30px 0;'>
                            <a href='{resetLink}' style='background-color: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;'>Reset Password</a>
                        </div>
                        <p>Or copy and paste this link into your browser:</p>
                        <p style='word-break: break-all; color: #007bff;'>{resetLink}</p>
                        <p>This link will expire in 1 hour.</p>
                        <p style='color: #666; font-size: 12px;'>If you did not request a password reset, please ignore this email.</p>
                    </div>
                </body>
                </html>";

            await SendEmailAsync(toEmail, subject, htmlBody);
        }
    }
}
