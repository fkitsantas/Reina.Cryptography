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
    internal class AzureKVKeyManager : IKeyManager
    {
        private readonly SecretClient _secretClient;
        private static readonly ConcurrentDictionary<string, byte[]> _keyCache = new ConcurrentDictionary<string, byte[]>();
        private static readonly Lazy<AzureKVKeyManager> _instance = new Lazy<AzureKVKeyManager>(() =>
        {
            return new AzureKVKeyManager(
                Config.Instance.AzureKeyVaultUrl,
                Config.Instance.AzureClientId,
                Config.Instance.AzureClientSecret,
                Config.Instance.AzureTenantId
            );
        });

        public static AzureKVKeyManager Instance => _instance.Value;

        public AzureKVKeyManager(string vaultUri, string clientId, string clientSecret, string tenantId)
        {
            var clientOptions = new SecretClientOptions();
            var clientCredential = new ClientSecretCredential(tenantId, clientId, clientSecret);
            _secretClient = new SecretClient(new Uri(vaultUri), clientCredential, clientOptions);
        }

        public async Task<byte[]> GetEncryptionKeyAsync(string keyName)
        {
            if (_keyCache.TryGetValue(keyName, out var cachedKey))
            {
                return cachedKey;
            }

            try
            {
                KeyVaultSecret secret = await _secretClient.GetSecretAsync(keyName);
                var key = Convert.FromBase64String(secret.Value);
                _keyCache[keyName] = key;
                return key;
            }
            catch (Azure.RequestFailedException ex) when (ex.Status == 404)
            {
                byte[] newKey = GenerateAES256Key();
                await _secretClient.SetSecretAsync(keyName, Convert.ToBase64String(newKey));
                _keyCache[keyName] = newKey;
                return newKey;
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

        private byte[] GenerateAES256Key()
        {
            using var aesAlg = Aes.Create();
            aesAlg.KeySize = 256;
            aesAlg.GenerateKey();
            return aesAlg.Key;
        }
    }
}
