namespace Reina.Cryptography.Interfaces
{
    internal interface IKeyManager
    {
        /// <summary>
        /// Asynchronously fetches the 256-bit key from Azure Key Vault.
        /// </summary>
        /// <param name="keyName">The name of the secret in Azure Key Vault that contains the encryption key.</param>
        /// <returns>A task that represents the asynchronous fetch operation. The value of the TResult parameter contains the fetched 256-bit key.</returns>
        Task<byte[]> GetEncryptionKeyAsync(string keyName);
    }
}
