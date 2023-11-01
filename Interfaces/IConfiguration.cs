namespace Reina.Cryptography.Interfaces
{
    internal interface IConfiguration
    {
        /// <summary>
        /// Gets the URL of the Azure Key Vault instance.
        /// </summary>
        string? AzureKeyVaultUrl { get; }

        /// <summary>
        /// Gets the client ID used for authentication with Azure Key Vault.
        /// </summary>
        string? AzureClientId { get; }

        /// <summary>
        /// Gets the client secret used for authentication with Azure Key Vault.
        /// </summary>
        string? AzureClientSecret { get; }

        /// <summary>
        /// Gets the tenant ID associated with the Azure subscription.
        /// </summary>
        string? AzureTenantId { get; }

        /// <summary>
        /// Validates the configuration settings to ensure they are correctly set.
        /// </summary>
        /// <exception cref="InvalidOperationException">Thrown when any of the configuration values are invalid or not set.</exception>
        void ValidateConfiguration();
    }
}