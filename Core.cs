using Reina.Cryptography.Encryption;
using Reina.Cryptography.Decryption;
using Reina.Cryptography.KeyManagement;
using System;
using System.Text;
using System.Threading.Tasks;

namespace Reina.Cryptography
{
    /// <summary>
    /// Provides core functionality for encryption and decryption of data,
    /// interfacing with Azure Key Vault for key management.
    /// </summary>
    public static class Core
    {
        /// <summary>
        /// Encrypts a plaintext string using three distinct keys for Twofish, Serpent, and AES encryption algorithms.
        /// </summary>
        /// <param name="decryptedString">The plaintext string to be encrypted.</param>
        /// <param name="twofishKeyName">The name of the Twofish key.</param>
        /// <param name="serpentKeyName">The name of the Serpent key.</param>
        /// <param name="aesKeyName">The name of the AES key.</param>
        /// <returns>A Base64-encoded string representing the encrypted data.</returns>
        /// <exception cref="ArgumentNullException">Thrown if the input string or any key name is null or empty.</exception>
        /// <exception cref="ArgumentException">Thrown if any key name does not adhere to the expected format.</exception>
        public static string Encrypt(string decryptedString, string twofishKeyName, string serpentKeyName, string aesKeyName)
        {
            // Input validation
            ValidateInput(decryptedString, twofishKeyName, serpentKeyName, aesKeyName);

            // Retrieve the encryption keys from the Azure Key Vault.
            byte[] twofishKey = AzureKVKeyManager.Instance.GetEncryptionKeyAsync(twofishKeyName).GetAwaiter().GetResult();
            byte[] serpentKey = AzureKVKeyManager.Instance.GetEncryptionKeyAsync(serpentKeyName).GetAwaiter().GetResult();
            byte[] aesKey = AzureKVKeyManager.Instance.GetEncryptionKeyAsync(aesKeyName).GetAwaiter().GetResult();

            // Initialize the encryptor with the retrieved key.
            var dataEncryptor = new DataEncryptor(twofishKey, serpentKey, aesKey);
            // Convert the plaintext string to a byte array.
            byte[] decryptedBytes = Encoding.UTF8.GetBytes(decryptedString);
            // Encrypt the data.
            byte[] encryptedBytes = dataEncryptor.Encrypt(decryptedBytes);

            // Return the encrypted data as a Base64 encoded string.
            return Convert.ToBase64String(encryptedBytes);
        }

        /// <summary>
        /// Decrypts a Base64-encoded string using three distinct keys for Twofish, Serpent, and AES encryption algorithms.
        /// </summary>
        /// <param name="encryptedString">The Base64-encoded string to be decrypted.</param>
        /// <param name="twofishKeyName">The name of the Twofish key.</param>
        /// <param name="serpentKeyName">The name of the Serpent key.</param>
        /// <param name="aesKeyName">The name of the AES key.</param>
        /// <returns>The decrypted plaintext string.</returns>
        /// <exception cref="ArgumentNullException">Thrown if the encrypted string or any key name is null or empty.</exception>
        /// <exception cref="ArgumentException">Thrown if any key name does not adhere to the expected format.</exception>
        public static string Decrypt(string encryptedString, string twofishKeyName, string serpentKeyName, string aesKeyName)
        {
            // Validate input parameters.
            ValidateInput(encryptedString, twofishKeyName, serpentKeyName, aesKeyName);

            // Retrieve the decryption keys from the Azure Key Vault.
            byte[] twofishKey = AzureKVKeyManager.Instance.GetEncryptionKeyAsync(twofishKeyName).GetAwaiter().GetResult();
            byte[] serpentKey = AzureKVKeyManager.Instance.GetEncryptionKeyAsync(serpentKeyName).GetAwaiter().GetResult();
            byte[] aesKey = AzureKVKeyManager.Instance.GetEncryptionKeyAsync(aesKeyName).GetAwaiter().GetResult();

            // Initialize the decryptor with the retrieved keys.
            var dataDecryptor = new DataDecryptor(twofishKey, serpentKey, aesKey);
            // Convert the Base64 encoded string to a byte array.
            byte[] encryptedBytes = Convert.FromBase64String(encryptedString);
            // Decrypt the data.
            byte[] decryptedBytes = dataDecryptor.Decrypt(encryptedBytes);

            // Return the decrypted data as a plaintext string.
            return Encoding.UTF8.GetString(decryptedBytes);
        }

        /// <summary>
        /// Validates the input string and key names, ensuring they are not null or empty and adhere to the expected format.
        /// </summary>
        /// <param name="input">The input string to validate.</param>
        /// <param name="keyNames">The key names to validate.</param>
        /// <exception cref="ArgumentNullException">Thrown if the input or any key name is null or empty.</exception>
        /// <exception cref="ArgumentException">Thrown if any key name does not match the required pattern.</exception>
        private static void ValidateInput(string input, params string[] keyNames)
        {
            // Validate that the input string is not null or empty.
            if (string.IsNullOrEmpty(input))
                throw new ArgumentNullException(nameof(input), "Input cannot be null or empty.");

            // Validate the format of each key name.
            foreach (var keyName in keyNames)
            {
                if (string.IsNullOrEmpty(keyName))
                    throw new ArgumentNullException(nameof(keyName), "Key name cannot be null or empty.");

                if (!System.Text.RegularExpressions.Regex.IsMatch(keyName, @"^[a-zA-Z][a-zA-Z0-9\-]{0,126}$"))
                    throw new ArgumentException("Invalid key name. A key name can be 1-127 characters, starting with a letter, containing only 0-9, a-z, A-Z, and -", nameof(keyName));
            }
        }


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
            return Encrypt(decryptedString, keyName, keyName, keyName);
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
            return Decrypt(encryptedString, keyName, keyName, keyName);
        }
    }
}