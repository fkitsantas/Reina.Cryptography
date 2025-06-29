using Reina.Cryptography.Configuration;
using Reina.Cryptography.Interfaces;
using System;
using System.Threading.Tasks;

namespace Reina.Cryptography.KeyManagement
{
    /// <summary>
    /// Provides a centralized access point to the appropriate IKeyManager implementation 
    /// based on the configured key management provider (Azure, AWS, GoogleCloud).
    /// </summary>
    internal static class KeyFactory
    {
        /// <summary>
        /// Asynchronously retrieves the appropriate IKeyManager implementation
        /// based on the configured provider.
        /// </summary>
        public static async Task<IKeyManager> InstanceAsync()
        {
            var cfg = Config.Instance;

            return cfg.Provider switch
            {
                "Azure" => await AzureKeyManager.InstanceAsync().ConfigureAwait(false),
                "AWS" => await AWSKeyManager.InstanceAsync().ConfigureAwait(false),
                "Google" => await GoogleCloudKeyManager.InstanceAsync().ConfigureAwait(false),
                _ => throw new InvalidOperationException($"Unsupported key management provider: {cfg.Provider}")
            };
        }
    }
}
