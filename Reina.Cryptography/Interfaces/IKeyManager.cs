namespace Reina.Cryptography.Interfaces
{
    /// <summary>
    /// Defines the contract for key management services responsible for providing encryption and decryption keys.
    /// </summary>
    public interface IKeyManager
    {
        /// <summary>
        /// Asynchronously retrieves the latest encryption key based on the provided base key name.
        /// </summary>
        /// <param name="keyName">The unique name of the key to retrieve.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the encryption key as a byte array.</returns>
        /// <exception cref="System.ArgumentNullException">Thrown when the keyName is null or empty.</exception>
        /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown when the key retrieval fails.</exception>
        Task<byte[]> GetEncryptionKeyAsync(string keyName);

        /// <summary>
        /// Asynchronously retrieves all valid decryption key versions based on the provided base key name.
        /// </summary>
        /// <param name="keyName">The base name of the key whose versions should be retrieved.</param>
        /// <returns>A task representing the asynchronous operation. The task result contains a list of byte arrays, each representing a decryption key.</returns>
        /// <exception cref="System.ArgumentNullException">Thrown when the keyName is null or empty.</exception>
        /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown when the key retrieval fails.</exception>
        Task<List<byte[]>> GetDecryptionKeysAsync(string keyName);
    }
}