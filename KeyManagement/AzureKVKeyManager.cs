using Azure.Core;
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
            var clientOptions = new SecretClientOptions
            {
                Retry =
                {
                    Delay = TimeSpan.FromSeconds(1),
                    MaxDelay = TimeSpan.FromSeconds(10),
                    MaxRetries = 5,
                    Mode = RetryMode.Exponential
                }
            };

            var credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
            _secretClient = new SecretClient(new Uri(vaultUri), credential, clientOptions);
        }

        /// <summary>
        /// Asynchronously retrieves an encryption key from Azure Key Vault or the local cache.
        /// </summary>
        /// <param name="baseKeyName">The name of the key to retrieve.</param>
        /// <returns>A byte array containing the encryption key.</returns>
        /// <exception cref="UnauthorizedAccessException">Thrown when authentication or authorization with Azure Key Vault fails.</exception>
        /// <exception cref="Exception">Thrown when an unexpected error occurs during key retrieval or generation.</exception>
        public async Task<byte[]> GetEncryptionKeyAsync(string baseKeyName)
        {
            try
            {
                if (_keyCache.TryGetValue(baseKeyName, out var cachedKey))
                    return cachedKey;

                var (versionedName, key) = await EnsureRotatedKeyAsync(baseKeyName).ConfigureAwait(false);
                _keyCache[baseKeyName] = key;
                return key;
            }
            catch (Azure.RequestFailedException ex) when (ex.Status == 401)
            {
                throw new UnauthorizedAccessException("Failed to authenticate with Azure Key Vault. Check credentials.", ex);
            }
            catch (Azure.RequestFailedException ex) when (ex.Status == 403)
            {
                throw new UnauthorizedAccessException("Access denied. Check Key Vault permissions.", ex);
            }
            catch (Azure.RequestFailedException ex)
            {
                throw new Exception($"Azure Key Vault error: {ex.Message}", ex);
            }
            catch (Exception ex)
            {
                throw new Exception($"Unexpected error in GetEncryptionKeyAsync: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Asynchronously retrieves an encryption key from Azure Key Vault or the local cache.
        /// </summary>
        /// <param name="baseKeyName">The base name of the key to retrieve (without version suffix).</param>
        /// <returns>A byte array containing the encryption key.</returns>
        /// <exception cref="UnauthorizedAccessException">Thrown when authentication or authorization with Azure Key Vault fails.</exception>
        /// <exception cref="Exception">Thrown when an unexpected error occurs during key retrieval or generation.</exception>

        public async Task<List<byte[]>> GetDecryptionKeysAsync(string baseKeyName)
        {
            var cfg = Config.Instance;
            var versionPattern = new Regex($"^{Regex.Escape(baseKeyName)}--v(\\d+)$", RegexOptions.Compiled);
            var versions = new List<(int Version, SecretProperties Props)>();

            try
            {
                await foreach (var prop in _secretClient.GetPropertiesOfSecretsAsync().ConfigureAwait(false))
                {
                    var match = versionPattern.Match(prop.Name);
                    if (match.Success && int.TryParse(match.Groups[1].Value, out int version))
                        versions.Add((version, prop));
                }

                if (versions.Count == 0)
                {
                    var freshKey = await GetEncryptionKeyAsync(baseKeyName).ConfigureAwait(false);
                    return new List<byte[]> { freshKey };
                }

                var sorted = versions.OrderByDescending(v => v.Version).ToList();
                var keys = new List<byte[]>();

                foreach (var (v, prop) in sorted)
                {
                    if (_keyCache.TryGetValue(prop.Name, out var cached))
                    {
                        keys.Add(cached);
                        continue;
                    }

                    try
                    {
                        var secret = (await _secretClient.GetSecretAsync(prop.Name).ConfigureAwait(false)).Value;
                        var key = Convert.FromBase64String(secret.Value);
                        _keyCache[prop.Name] = key;
                        keys.Add(key);
                    }
                    catch
                    {
                        // Ignore and skip missing/invalid secrets
                    }
                }

                // Ensure rotation during decryption flow
                await EnsureRotatedKeyAsync(baseKeyName).ConfigureAwait(false);

                return keys;
            }
            catch (Azure.RequestFailedException ex) when (ex.Status == 401)
            {
                throw new UnauthorizedAccessException("Failed to authenticate with Azure Key Vault. Please check your credentials.", ex);
            }
            catch (Azure.RequestFailedException ex) when (ex.Status == 403)
            {
                throw new UnauthorizedAccessException("Access denied. The application does not have the necessary permissions to access the Azure Key Vault secret.", ex);
            }
            catch (Azure.RequestFailedException ex)
            {
                throw new Exception($"An error occurred while accessing Azure Key Vault: {ex.Message}", ex);
            }
            catch (Exception ex)
            {
                throw new Exception($"An unexpected error occurred: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Ensures that a cryptographic key is present and rotated if necessary based on the configured threshold.
        /// If no key exists, it creates the initial version. If the latest version is older than the rotation threshold, it creates a new version.
        /// Also cleans up versions older than the configured retention period.
        /// </summary>
        /// <param name="baseKeyName">The base name of the key (without version suffix).</param>
        /// <returns>
        /// A tuple containing the versioned key name and the associated 256-bit key as a byte array.
        /// </returns>
        /// <exception cref="UnauthorizedAccessException">
        /// Thrown when authentication or authorization with Azure Key Vault fails.
        /// </exception>
        /// <exception cref="Exception">
        /// Thrown when an error occurs during the retrieval, creation, or rotation of secrets.
        /// </exception>
        private async Task<(string versionedName, byte[] key)> EnsureRotatedKeyAsync(string baseKeyName)
        {
            try
            {
                var cfg = Config.Instance;
                var versionPattern = new Regex($"^{Regex.Escape(baseKeyName)}--v(\\d+)$", RegexOptions.Compiled);
                var versions = new List<(int, SecretProperties)>();

                await foreach (var prop in _secretClient.GetPropertiesOfSecretsAsync())
                {
                    var match = versionPattern.Match(prop.Name);
                    if (match.Success && int.TryParse(match.Groups[1].Value, out int version))
                        versions.Add((version, prop));
                }

                if (versions.Count == 0)
                {
                    string name = $"{baseKeyName}--v1";
                    byte[] key = Generate256bitKey();
                    await _secretClient.SetSecretAsync(name, Convert.ToBase64String(key)).ConfigureAwait(false);
                    return (name, key);
                }

                var sorted = versions.OrderByDescending(v => v.Item1).ToList();
                var (latestVersion, latestProp) = sorted.First();
                var created = latestProp.CreatedOn ?? DateTimeOffset.UtcNow;

                if (created.Add(cfg.KeyRotationThreshold) <= DateTimeOffset.UtcNow)
                {
                    int newVersion = latestVersion + 1;
                    string name = $"{baseKeyName}--v{newVersion}";
                    byte[] key = Generate256bitKey();
                    await _secretClient.SetSecretAsync(name, Convert.ToBase64String(key)).ConfigureAwait(false);

                    var cutoff = DateTimeOffset.UtcNow.Subtract(cfg.KeyRetentionPeriod);
                    foreach (var (_, prop) in sorted)
                    {
                        if ((prop.CreatedOn ?? DateTimeOffset.UtcNow) < cutoff)
                            try { await _secretClient.StartDeleteSecretAsync(prop.Name).ConfigureAwait(false); } catch { }
                    }

                    return (name, key);
                }
                else
                {
                    var secret = await _secretClient.GetSecretAsync(latestProp.Name);
                    return (latestProp.Name, Convert.FromBase64String(secret.Value.Value));
                }
            }
            catch (Azure.RequestFailedException ex) when (ex.Status == 401)
            {
                throw new UnauthorizedAccessException("Failed to authenticate with Azure Key Vault. Check credentials.", ex);
            }
            catch (Azure.RequestFailedException ex) when (ex.Status == 403)
            {
                throw new UnauthorizedAccessException("Access denied. Check Key Vault permissions.", ex);
            }
            catch (Azure.RequestFailedException ex)
            {
                throw new Exception($"Azure Key Vault error: {ex.Message}", ex);
            }
            catch (Exception ex)
            {
                throw new Exception($"Unexpected error in EnsureRotatedKeyAsync: {ex.Message}", ex);
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