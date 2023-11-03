using System.Threading.Tasks;

namespace Reina.Cryptography.Interfaces
{
    /// <summary>
    /// Defines the contract for the DataDecryptor class that implements data decryption.
    /// </summary>
    internal interface IDecryptor
    {
        /// <summary>
        /// Decrypts the specified data.
        /// </summary>
        /// <param name="data">The encrypted data to be decrypted.</param>
        /// <returns>The decrypted data as a byte array.</returns>
        /// <exception cref="System.ArgumentNullException">Thrown when the input data is null.</exception>
        /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown when decryption fails due to cryptographic errors such as invalid padding or incorrect keys.</exception>
        /// <exception cref="System.ArgumentException">Thrown when the input data is in an invalid format or corrupted.</exception>
        byte[] Decrypt(byte[] data);
    }
}
