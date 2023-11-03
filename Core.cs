using Reina.Cryptography.Encryption;
using Reina.Cryptography.Decryption;
using Reina.Cryptography.KeyManagement;
using System;
using System.Text;
using System.Threading.Tasks;

namespace Reina.Cryptography
{
    /// <summary>
    /// Provides core functionality for encryption and decryption of data.
    /// </summary>
    public static class Core
    {
        /// <summary>
        /// Encrypts a plaintext string synchronously using a specified key retrieved asynchronously from Azure Key Vault.
        /// The encryption process is a multi-layered approach that ensures data confidentiality.
        /// </summary>
        /// <param name="decryptedString">The plaintext string to be encrypted.</param>
        /// <param name="keyName">The name of the key to use for encryption.</param>
        /// <returns>A Base64-encoded string that represents the encrypted data.</returns>
        /// <exception cref="ArgumentNullException">Thrown if the input string or key name is null or empty.</exception>
        /// <exception cref="ArgumentException">Thrown if the key name does not adhere to the expected format.</exception>
        public static string Encrypt(string decryptedString, string keyName)
        {
            // Validate that the decrypted string is not null or empty.
            if (string.IsNullOrEmpty(decryptedString))
                throw new ArgumentNullException(nameof(decryptedString), "Input string cannot be null or empty.");

            // Validate that the key name is not null or empty.
            if (string.IsNullOrEmpty(keyName))
                throw new ArgumentNullException(nameof(keyName), "Key name cannot be null or empty.");

            // Validate the format of the key name.
            if (!System.Text.RegularExpressions.Regex.IsMatch(keyName, @"^[a-zA-Z][a-zA-Z0-9\-]{0,126}$"))
                throw new ArgumentException("Invalid key name.", nameof(keyName));

            // Retrieve the encryption key from the Azure Key Vault.
            byte[] encryptionKey = AzureKVKeyManager.Instance.GetEncryptionKeyAsync(keyName).GetAwaiter().GetResult();

            // Initialize the encryptor with the retrieved key.
            var dataEncryptor = new DataEncryptor(encryptionKey);

            // Convert the plaintext string to a byte array.
            byte[] decryptedBytes = Encoding.UTF8.GetBytes(decryptedString);

            // Encrypt the data.
            byte[] encryptedBytes = dataEncryptor.Encrypt(decryptedBytes);

            // Return the encrypted data as a Base64 encoded string.
            return Convert.ToBase64String(encryptedBytes);
        }

        /// <summary>
        /// Decrypts a Base64-encoded string synchronously using a specified key retrieved asynchronously from Azure Key Vault.
        /// The decryption process reverses the multi-layered encryption to restore the original plaintext.
        /// </summary>
        /// <param name="encryptedString">The Base64-encoded string to be decrypted.</param>
        /// <param name="keyName">The name of the key to use for decryption.</param>
        /// <returns>The decrypted plaintext string.</returns>
        /// <exception cref="ArgumentNullException">Thrown if the encrypted string or key name is null or empty.</exception>
        /// <exception cref="ArgumentException">Thrown if the key name does not adhere to the expected format.</exception>
        public static string Decrypt(string encryptedString, string keyName)
        {
            // Validate that the encrypted string is not null or empty.
            if (string.IsNullOrEmpty(encryptedString))
                throw new ArgumentNullException(nameof(encryptedString), "Encrypted string cannot be null or empty.");

            // Validate that the key name is not null or empty.
            if (string.IsNullOrEmpty(keyName))
                throw new ArgumentNullException(nameof(keyName), "Key name cannot be null or empty.");

            // Validate the format of the key name.
            if (!System.Text.RegularExpressions.Regex.IsMatch(keyName, @"^[a-zA-Z][a-zA-Z0-9\-]{0,126}$"))
                throw new ArgumentException("Invalid key name.", nameof(keyName));

            // Retrieve the decryption key from the Azure Key Vault.
            byte[] decryptionKey = AzureKVKeyManager.Instance.GetEncryptionKeyAsync(keyName).GetAwaiter().GetResult();

            // Initialize the decryptor with the retrieved key.
            var dataDecryptor = new DataDecryptor(decryptionKey);

            // Convert the Base64 encoded string to a byte array.
            byte[] encryptedBytes = Convert.FromBase64String(encryptedString);

            // Decrypt the data.
            byte[] decryptedBytes = dataDecryptor.Decrypt(encryptedBytes);

            // Return the decrypted data as a plaintext string.
            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}