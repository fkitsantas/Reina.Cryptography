using Microsoft.Extensions.Configuration;
using Reina.Cryptography.Interfaces;
using System;
using System.IO;
using System.Reflection;

namespace Reina.Cryptography.Configuration
{
    internal class Config : ILibraryConfiguration
    {
        // Singleton instance
        private static readonly Lazy<Config> _instance = new(() => new Config());
        public static Config Instance => _instance.Value;

        // Internal config root
        private readonly IConfigurationRoot _cfg;

        // Backing config values
        private int KeyRotationThresholdDays { get; }
        private int KeyRetentionPeriodDays { get; }

        // Constructor (private to enforce singleton)
        private Config()
        {
            var builder = new ConfigurationBuilder();

#if NETFRAMEWORK
            using var stream = Assembly.GetExecutingAssembly()
                .GetManifestResourceStream("Reina.Cryptography.appsettings.json")
                ?? throw new InvalidOperationException("Embedded appsettings.json not found.");
            builder.AddJsonStream(stream);
#else
            builder.SetBasePath(AppContext.BaseDirectory)
                   .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false);
#endif
            _cfg = builder.Build();
            var km = _cfg.GetSection("KeyManagement");

            Provider = km["Provider"] ?? throw new InvalidOperationException("KeyManagement:Provider is required");

            var policy = km.GetSection("RotationPolicy");
            KeyRotationThresholdDays = int.TryParse(policy["KeyRotationThresholdDays"], out var r) ? r : 90;
            KeyRetentionPeriodDays = int.TryParse(policy["KeyRetentionPeriodDays"], out var t) ? t : 365;

            switch (Provider)
            {
                case "Azure":
                    var az = km.GetSection("Azure");
                    AzureKeyVaultUrl = az["KeyVaultUrl"] ?? throw new InvalidOperationException("Azure:KeyVaultUrl is required");
                    AzureClientId = az["ClientId"] ?? throw new InvalidOperationException("Azure:ClientId is required");
                    AzureClientSecret = az["ClientSecret"] ?? throw new InvalidOperationException("Azure:ClientSecret is required");
                    AzureTenantId = az["TenantId"] ?? throw new InvalidOperationException("Azure:TenantId is required");
                    break;

                case "AWS":
                    var aws = km.GetSection("AWS");
                    AWSRegion = aws["Region"] ?? throw new InvalidOperationException("AWS:Region is required");
                    AWSAccessKeyId = aws["AccessKeyId"];
                    AWSSecretAccessKey = aws["SecretAccessKey"];
                    break;

                case "GoogleCloud":
                    var google = km.GetSection("GoogleCloud");
                    GoogleProjectId = google["ProjectId"] ?? throw new InvalidOperationException("GoogleCloud:ProjectId is required");
                    GoogleCredentialsJsonPath = google["CredentialsJsonPath"];
                    break;

                default:
                    throw new InvalidOperationException($"Unknown provider: {Provider}");
            };
        }

        // Public API - Properties (exposed via interface)
        public string Provider { get; }
        public TimeSpan KeyRotationThreshold => TimeSpan.FromDays(KeyRotationThresholdDays);
        public TimeSpan KeyRetentionPeriod => TimeSpan.FromDays(KeyRetentionPeriodDays);

        // Azure config
        public string? AzureKeyVaultUrl { get; } = null;
        public string? AzureClientId { get; } = null;
        public string? AzureClientSecret { get; } = null;
        public string? AzureTenantId { get; } = null;

        // AWS config
        public string? AWSRegion { get; } = null;
        public string? AWSAccessKeyId { get; } = null;
        public string? AWSSecretAccessKey { get; } = null;

        // GoogleCloud config
        public string? GoogleProjectId { get; } = null;
        public string? GoogleCredentialsJsonPath { get; } = null;

        // Public method to validate required config per provider
        public void ValidateConfiguration()
        {
            if (string.IsNullOrWhiteSpace(Provider))
                throw new InvalidOperationException("KeyManagement:Provider must be set.");

            switch (Provider)
            {
                case "Azure":
                    if (string.IsNullOrWhiteSpace(AzureKeyVaultUrl)
                     || string.IsNullOrWhiteSpace(AzureClientId)
                     || string.IsNullOrWhiteSpace(AzureClientSecret)
                     || string.IsNullOrWhiteSpace(AzureTenantId))
                        throw new InvalidOperationException("Incomplete Azure settings.");
                    break;

                case "AWS":
                    if (string.IsNullOrWhiteSpace(AWSRegion))
                        throw new InvalidOperationException("AWS Region must be set.");
                    break;

                case "Google":
                    if (string.IsNullOrWhiteSpace(GoogleProjectId))
                        throw new InvalidOperationException("Google ProjectId must be set.");
                    break;

                default:
                    throw new InvalidOperationException($"Unknown Provider '{Provider}'.");
            }
        }
    }
}