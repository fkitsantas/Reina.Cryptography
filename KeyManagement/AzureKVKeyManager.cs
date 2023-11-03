using Reina.Cryptography.Interfaces;
using Reina.Cryptography.Configuration;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using System;
using System.Security.Cryptography;
using System.Collections.Concurrent;
using System.Threading.Tasks;

namespace Reina.Cryptography.KeyManagement
{
    /// <summary>
    /// Manages 256bit cryptographic keys by interfacing with Azure Key Vault.
    /// </summary>
    internal class AzureKVKeyManager : IKeyManager
    {
        private readonly SecretClient _secretClient;
        private static readonly ConcurrentDictionary<string, byte[]> _keyCache = new();

        // Lazy initialization of the AzureKVKeyManager singleton instance.
        private static readonly Lazy<AzureKVKeyManager> _instance = new(() =>
        {
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
        public async Task<byte[]> GetEncryptionKeyAsync(string keyName)
        {
            // Attempt to retrieve the key from cache.
            if (_keyCache.TryGetValue(keyName, out var cachedKey))
            {
                return cachedKey;
            }

            try
            {
                // Retrieve the key from Azure Key Vault.
                KeyVaultSecret secret = await _secretClient.GetSecretAsync(keyName);
                var key = Convert.FromBase64String(secret.Value);
                _keyCache[keyName] = key;
                return key;
            }
            catch (Azure.RequestFailedException ex) when (ex.Status == 404)
            {
                // If the key is not found, generate a new one, store it, and return it.
                byte[] newKey = Generate256bitKey();
                await _secretClient.SetSecretAsync(keyName, Convert.ToBase64String(newKey));
                _keyCache[keyName] = newKey;
                return newKey;
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