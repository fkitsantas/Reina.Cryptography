using System;
using Reina.Cryptography.Interfaces;

namespace Reina.Cryptography.Configuration
{
    internal class Config : IConfiguration
    {
        // Singleton instance
        private static readonly Lazy<Config> _instance = new Lazy<Config>(() => new Config());

        // Private constructor to prevent multiple instances
        private Config() { }

        // Public method to access the singleton instance
        public static Config Instance => _instance.Value;

        public string AzureKeyVaultUrl { get; } = "the-azure-key-vault-url";
        public string AzureClientId { get; } = "the-client-id";
        public string AzureClientSecret { get; } = "the-azure-client-secret";
        public string AzureTenantId { get; } = "the-azure-tenant-id";

        public void ValidateConfiguration()
        {
            if (string.IsNullOrWhiteSpace(AzureKeyVaultUrl) || string.IsNullOrWhiteSpace(AzureClientId) || string.IsNullOrWhiteSpace(AzureClientSecret) || string.IsNullOrWhiteSpace(AzureTenantId))
            {
                throw new InvalidOperationException("Invalid Azure Key Vault configuration. Ensure all configuration values are set.");
            }
        }
    }
}
