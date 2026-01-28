using Newtonsoft.Json;

namespace Application_Security_ASSGN2.Services
{
    public interface IReCaptchaService
    {
        Task<bool> VerifyTokenAsync(string token);
        Task<ReCaptchaResponse> VerifyTokenWithDetailsAsync(string token);
    }

    public class ReCaptchaResponse
    {
        [JsonProperty("success")]
        public bool Success { get; set; }

        [JsonProperty("score")]
        public float Score { get; set; }

        [JsonProperty("action")]
        public string? Action { get; set; }

        [JsonProperty("challenge_ts")]
        public DateTime ChallengeTimestamp { get; set; }

        [JsonProperty("hostname")]
        public string? Hostname { get; set; }

        [JsonProperty("error-codes")]
        public List<string>? ErrorCodes { get; set; }
    }

    public class ReCaptchaService : IReCaptchaService
    {
        private readonly HttpClient _httpClient;
        private readonly string _secretKey;
        private readonly ILogger<ReCaptchaService> _logger;
        private const string VerifyUrl = "https://www.google.com/recaptcha/api/siteverify";
        private const float MinimumScore = 0.5f;

        public ReCaptchaService(IConfiguration configuration, IHttpClientFactory httpClientFactory, ILogger<ReCaptchaService> logger)
        {
            _httpClient = httpClientFactory.CreateClient();
            _secretKey = configuration["ReCaptcha:SecretKey"] 
                ?? throw new InvalidOperationException("ReCaptcha secret key not configured");
            _logger = logger;
        }

        public async Task<bool> VerifyTokenAsync(string token)
        {
            var response = await VerifyTokenWithDetailsAsync(token);
            return response.Success && response.Score >= MinimumScore;
        }

        public async Task<ReCaptchaResponse> VerifyTokenWithDetailsAsync(string token)
        {
            try
            {
                if (string.IsNullOrEmpty(token))
                {
                    return new ReCaptchaResponse { Success = false, ErrorCodes = new List<string> { "missing-input-response" } };
                }

                var parameters = new Dictionary<string, string>
                {
                    { "secret", _secretKey },
                    { "response", token }
                };

                var content = new FormUrlEncodedContent(parameters);
                var response = await _httpClient.PostAsync(VerifyUrl, content);

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogError("reCAPTCHA verification request failed with status code: {StatusCode}", response.StatusCode);
                    return new ReCaptchaResponse { Success = false, ErrorCodes = new List<string> { "request-failed" } };
                }

                var jsonResponse = await response.Content.ReadAsStringAsync();
                var result = JsonConvert.DeserializeObject<ReCaptchaResponse>(jsonResponse);

                if (result == null)
                {
                    return new ReCaptchaResponse { Success = false, ErrorCodes = new List<string> { "invalid-response" } };
                }

                _logger.LogInformation("reCAPTCHA verification result: Success={Success}, Score={Score}", result.Success, result.Score);

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error verifying reCAPTCHA token");
                return new ReCaptchaResponse { Success = false, ErrorCodes = new List<string> { "exception" } };
            }
        }
    }
}
