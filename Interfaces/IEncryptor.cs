using System.Threading.Tasks;

namespace Reina.Cryptography.Interfaces
{
    internal interface IEncryptor
    {
        /// <summary>
        /// Asynchronously encrypts the provided data.
        /// </summary>
        /// <param name="data">The data to be encrypted.</param>
        /// <returns>A task that represents the asynchronous encryption operation. The value of the TResult parameter contains the encrypted data.</returns>
        Task<byte[]> EncryptAsync(byte[] data);
    }
}
