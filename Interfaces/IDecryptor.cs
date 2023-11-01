using System.Threading.Tasks;

namespace Reina.Cryptography.Interfaces
{
    internal interface IDecryptor
    {
        /// <summary>
        /// Asynchronously decrypts the provided encrypted data.
        /// </summary>
        /// <param name="data">The data to be decrypted.</param>
        /// <returns>A task that represents the asynchronous decryption operation. The value of the TResult parameter contains the decrypted data.</returns>
        Task<byte[]> DecryptAsync(byte[] data);
    }
}
