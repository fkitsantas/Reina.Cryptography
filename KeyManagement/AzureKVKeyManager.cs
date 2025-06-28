using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Reina.Cryptography.Configuration;
using Reina.Cryptography.Interfaces;
using System;
using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Reina.Cryptography.KeyManagement
{
    /// <summary>
    /// Manages 256-bit cryptographic keys by interfacing with Azure Key Vault, providing secure storage and retrieval of keys.
    /// This class implements a caching mechanism to optimize key retrieval performance by reducing the number of round trips to the key vault.
    /// </summary>
    internal class AzureKVKeyManager : IKeyManager
    {
        private readonly SecretClient _secretClient;
        private static readonly ConcurrentDictionary<string, byte[]> _keyCache = new();

        // Lazy initialization of the AzureKVKeyManager singleton instance.
        private static readonly Lazy<AzureKVKeyManager> _instance = new(() =>
        {
            Config.Instance.ValidateConfiguration(); // Validate Azure KV Configuration
            return new AzureKVKeyManager(
                Config.Instance.AzureKeyVaultUrl,
                Config.Instance.AzureClientId,
                Config.Instance.AzureClientSecret,
                Config.Instance.AzureTenantId
            );
        });

        /// <summary>
        /// Gets the singleton instance of the AzureKVKeyManager.
        /// </summary>
        public static AzureKVKeyManager Instance => _instance.Value;

        /// <summary>
        /// Initializes a new instance of the AzureKVKeyManager class.
        /// </summary>
        /// <param name="vaultUri">The URI of the Azure Key Vault.</param>
        /// <param name="clientId">The client ID for Azure Active Directory authentication.</param>
        /// <param name="clientSecret">The client secret for Azure Active Directory authentication.</param>
        /// <param name="tenantId">The tenant ID for Azure Active Directory authentication.</param>
        public AzureKVKeyManager(string vaultUri, string clientId, string clientSecret, string tenantId)
        {
            SecretClientOptions clientOptions = new();
            ClientSecretCredential clientCredential = new(tenantId, clientId, clientSecret);
            _secretClient = new SecretClient(new Uri(vaultUri), clientCredential, clientOptions);
        }

        /// <summary>
        /// Asynchronously retrieves an encryption key from Azure Key Vault or the local cache.
        /// </summary>
        /// <param name="keyName">The name of the key to retrieve.</param>
        /// <returns>A byte array containing the encryption key.</returns>
        /// <exception cref="UnauthorizedAccessException">Thrown when authentication or authorization with Azure Key Vault fails.</exception>
        /// <exception cref="Exception">Thrown when an unexpected error occurs during key retrieval or generation.</exception>
        public async Task<byte[]> GetEncryptionKeyAsync(string keyName)
        {
            // Attempt to retrieve the key from cache.
            if (_keyCache.TryGetValue(keyName, out var cachedKey))
                return cachedKey;

            var cfg = Config.Instance;
            var versionPattern = new Regex($"^{Regex.Escape(keyName)}--v(\\d+)$", RegexOptions.Compiled);
            var versions = new List<(int Version, SecretProperties Props)>();

            try
            {
                await foreach (var prop in _secretClient.GetPropertiesOfSecretsAsync())
                {
                    var match = versionPattern.Match(prop.Name);
                    if (match.Success && int.TryParse(match.Groups[1].Value, out int version))
                    {
                        versions.Add((version, prop));
                    }
                }

                string resolvedKeyName;
                byte[] resolvedKey;

                if (versions.Count == 0)
                {
                    resolvedKeyName = $"{keyName}--v1";
                    resolvedKey = Generate256bitKey();
                    await _secretClient.SetSecretAsync(resolvedKeyName, Convert.ToBase64String(resolvedKey));
                }
                else
                {
                    var sorted = versions.OrderByDescending(x => x.Version).ToList();
                    var (latestVersion, latestProp) = sorted.First();
                    var created = latestProp.CreatedOn ?? DateTimeOffset.UtcNow;

                    if (created.Add(cfg.KeyRotationThreshold) <= DateTimeOffset.UtcNow)
                    {
                        // Rotate
                        int newVersion = latestVersion + 1;
                        resolvedKeyName = $"{keyName}--v{newVersion}";
                        resolvedKey = Generate256bitKey();
                        await _secretClient.SetSecretAsync(resolvedKeyName, Convert.ToBase64String(resolvedKey));
                    }
                    else
                    {
                        // Use existing latest
                        resolvedKeyName = latestProp.Name;
                        KeyVaultSecret secret = (await _secretClient.GetSecretAsync(resolvedKeyName)).Value;
                        resolvedKey = Convert.FromBase64String(secret.Value);
                    }

                    // Cleanup old versions
                    var cutoff = DateTimeOffset.UtcNow.Subtract(cfg.KeyRetentionPeriod);
                    foreach (var (v, prop) in sorted)
                    {
                        if ((prop.CreatedOn ?? DateTimeOffset.UtcNow) < cutoff)
                        {
                            try { await _secretClient.StartDeleteSecretAsync(prop.Name); } 
                            catch { /* Ignore errors during deletion */}
                        }
                    }
                }

                _keyCache[keyName] = resolvedKey;
                return resolvedKey;
            }
            catch (Azure.RequestFailedException ex) when (ex.Status == 401)
            {
                // Handles authentication failures.
                throw new UnauthorizedAccessException("Failed to authenticate with Azure Key Vault. Please check your credentials.", ex);
            }
            catch (Azure.RequestFailedException ex) when (ex.Status == 403)
            {
                // Handles authorization failures.
                throw new UnauthorizedAccessException("Access denied. The application does not have the necessary permissions to access the Azure Key Vault secret.", ex);
            }
            catch (Azure.RequestFailedException ex)
            {
                // Handles general Azure Key Vault access errors.
                throw new Exception($"An error occurred while accessing Azure Key Vault: {ex.Message}", ex);
            }
            catch (Exception ex)
            {
                // Handles all other exceptions.
                throw new Exception($"An unexpected error occurred: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Generates a new 256-bit cryptographic key.
        /// </summary>
        /// <returns>A byte array containing the generated key.</returns>
        private byte[] Generate256bitKey()
        {
            using var aesAlg = Aes.Create();
            aesAlg.KeySize = 256;
            aesAlg.GenerateKey();
            return aesAlg.Key;
        }
    }
}