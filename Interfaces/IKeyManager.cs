namespace Reina.Cryptography.Interfaces
{
    /// <summary>
    /// Defines the contract for key management services responsible for providing encryption keys.
    /// </summary>
    internal interface IKeyManager
    {
        /// <summary>
        /// Asynchronously retrieves a 256bit encryption key based on the provided key name.
        /// </summary>
        /// <param name="keyName">The unique name of the key to retrieve.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the encryption key as a byte array.</returns>
        /// <exception cref="System.ArgumentNullException">Thrown when the keyName is null or empty.</exception>
        /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown when the key retrieval fails due to issues such as missing key, access issues, or backend service errors.</exception>
        Task<byte[]> GetEncryptionKeyAsync(string keyName);
    }
}