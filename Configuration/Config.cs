using Reina.Cryptography.Interfaces;
using System;

namespace Reina.Cryptography.Configuration
{
    /// <summary>
    /// Represents the configuration settings for accessing Azure Key Vault.
    /// This class follows the Singleton design pattern to ensure that only one instance holds the configuration values.
    /// </summary>
    internal class Config : IConfiguration
    {
        /// <summary>
        /// Holds the lazy-loaded singleton instance of the configuration.
        /// </summary>
        private static readonly Lazy<Config> _instance = new(() => new Config());

        /// <summary>
        /// Private constructor to prevent instantiation outside of the Singleton instance.
        /// </summary>
        private Config() { }

        /// <summary>
        /// Provides global access to the singleton instance of the configuration.
        /// </summary>
        public static Config Instance => _instance.Value;

        /// <summary>
        /// The URL of the Azure Key Vault.
        /// </summary>
        public string AzureKeyVaultUrl { get; } = "the-azure-key-vault-url";

        /// <summary>
        /// The client ID for Azure Key Vault authentication.
        /// </summary>
        public string AzureClientId { get; } = "the-client-id";

        /// <summary>
        /// The client secret for Azure Key Vault authentication.
        /// </summary>
        public string AzureClientSecret { get; } = "the-azure-client-secret";

        /// <summary>
        /// The tenant ID for Azure Key Vault authentication.
        /// </summary>
        public string AzureTenantId { get; } = "the-azure-tenant-id";

        /// <summary>
        /// Validates the configuration settings for Azure Key Vault access.
        /// Throws an exception if any configuration value is not properly set.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown when any of the Azure Key Vault configuration values are not set or are whitespace.</exception>
        public void ValidateConfiguration()
        {
            // Ensure that all required configuration values are set and not just whitespace.
            if (string.IsNullOrWhiteSpace(AzureKeyVaultUrl) ||
                string.IsNullOrWhiteSpace(AzureClientId) ||
                string.IsNullOrWhiteSpace(AzureClientSecret) ||
                string.IsNullOrWhiteSpace(AzureTenantId))
            {
                throw new InvalidOperationException("Invalid Azure Key Vault configuration. Ensure all configuration values are set.");
            }
        }
    }
}