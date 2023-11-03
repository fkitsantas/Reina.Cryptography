using System.Threading.Tasks;

namespace Reina.Cryptography.Interfaces
{
    /// <summary>
    /// Defines the contract for the DataEncryptor class that implements data encryption.
    /// </summary>
    internal interface IEncryptor
    {
        /// <summary>
        /// Encrypts the specified data.
        /// </summary>
        /// <param name="data">The plaintext data to be encrypted.</param>
        /// <returns>The encrypted data as a byte array.</returns>
        /// <exception cref="System.ArgumentNullException">Thrown when the input data is null.</exception>
        /// <exception cref="System.Security.Cryptography.CryptographicException">Thrown when encryption fails due to cryptographic errors such as invalid key size or algorithm constraints.</exception>
        byte[] Encrypt(byte[] data);
    }
}