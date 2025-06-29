namespace Reina.Cryptography.Interfaces
{
    /// <summary>
    /// Represents configuration settings required for key management across different cloud providers.
    /// </summary>
    public interface ILibraryConfiguration
    {
        /// <summary>
        /// Gets the name of the configured key management provider (e.g., Azure, AWS, Google).
        /// </summary>
        string Provider { get; }

        /// <summary>
        /// Gets the key rotation threshold as a <see cref="TimeSpan"/>.
        /// </summary>
        TimeSpan KeyRotationThreshold { get; }

        /// <summary>
        /// Gets the key retention period as a <see cref="TimeSpan"/>.
        /// </summary>
        TimeSpan KeyRetentionPeriod { get; }

        // Azure
        /// <summary>Gets the Azure Key Vault URL.</summary>
        string? AzureKeyVaultUrl { get; }

        /// <summary>Gets the Azure client ID.</summary>
        string? AzureClientId { get; }

        /// <summary>Gets the Azure client secret.</summary>
        string? AzureClientSecret { get; }

        /// <summary>Gets the Azure tenant ID.</summary>
        string? AzureTenantId { get; }

        // AWS
        /// <summary>Gets the AWS region.</summary>
        string? AWSRegion { get; }

        /// <summary>Gets the AWS access key ID.</summary>
        string? AWSAccessKeyId { get; }

        /// <summary>Gets the AWS secret access key.</summary>
        string? AWSSecretAccessKey { get; }

        // Google
        /// <summary>Gets the Google Cloud project ID.</summary>
        string? GoogleProjectId { get; }

        /// <summary>Gets the path to the Google credentials JSON.</summary>
        string? GoogleCredentialsJsonPath { get; }

        /// <summary>
        /// Validates the configuration to ensure all required values are properly set.
        /// </summary>
        void ValidateConfiguration();
    }
}