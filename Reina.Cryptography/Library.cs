using Reina.Cryptography.Configuration;
using Reina.Cryptography.Decryption;
using Reina.Cryptography.Encryption;
using Reina.Cryptography.KeyManagement;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace Reina.Cryptography
{
    /// <summary>
    /// Provides core functionality for encryption and decryption of data,
    /// interfacing with a cloud-based key management provider.
    /// </summary>
    public static class Library
    {
        static Library()
        {
            Config.Instance.ValidateConfiguration(); // Ensure configuration is valid
        }

        /// <summary>
        /// Encrypts a plaintext string using three distinct keys for Twofish, Serpent, and AES encryption algorithms.
        /// This method is synchronous and blocks the calling thread.
        /// </summary>
        /// <param name="decryptedString">The plaintext string to be encrypted.</param>
        /// <param name="twofishKeyName">The name of the Twofish key.</param>
        /// <param name="serpentKeyName">The name of the Serpent key.</param>
        /// <param name="aesKeyName">The name of the AES key.</param>
        /// <returns>A Base64-encoded string representing the encrypted data.</returns>
        [Obsolete("This method is obsolete. Use EncryptAsync instead to avoid blocking the calling thread.")]
        public static string Encrypt(string decryptedString, string twofishKeyName, string serpentKeyName, string aesKeyName) =>
            EncryptAsync(decryptedString, twofishKeyName, serpentKeyName, aesKeyName).GetAwaiter().GetResult();

        /// <summary>
        /// Encrypts a plaintext string synchronously using a specified key retrieved asynchronously from the key management provider.
        /// The encryption process is a multi-layered approach that ensures data confidentiality.
        /// </summary>
        /// <param name="decryptedString">The plaintext string to be encrypted.</param>
        /// <param name="keyName">The name of the key to use for encryption.</param>
        /// <returns>A Base64-encoded string that represents the encrypted data.</returns>
        [Obsolete("This method is obsolete. Use EncryptAsync instead to avoid blocking the calling thread.")]
        public static string Encrypt(string decryptedString, string keyName) =>
            Encrypt(decryptedString, keyName, keyName, keyName);

        /// <summary>
        /// Decrypts a Base64-encoded string using three distinct keys for Twofish, Serpent, and AES encryption algorithms.
        /// This method is synchronous and blocks the calling thread.
        /// </summary>
        /// <param name="encryptedString">The Base64-encoded string to be decrypted.</param>
        /// <param name="twofishKeyName">The name of the Twofish key.</param>
        /// <param name="serpentKeyName">The name of the Serpent key.</param>
        /// <param name="aesKeyName">The name of the AES key.</param>
        /// <returns>The decrypted plaintext string.</returns>
        [Obsolete("This method is obsolete. Use DecryptAsync instead to avoid blocking the calling thread.")]
        public static string Decrypt(string encryptedString, string twofishKeyName, string serpentKeyName, string aesKeyName) =>
            DecryptAsync(encryptedString, twofishKeyName, serpentKeyName, aesKeyName).GetAwaiter().GetResult();

        /// <summary>
        /// Decrypts a Base64-encoded string synchronously using a specified key retrieved asynchronously from the key management provider.
        /// The decryption process reverses the multi-layered encryption to restore the original plaintext.
        /// </summary>
        /// <param name="encryptedString">The Base64-encoded string to be decrypted.</param>
        /// <param name="keyName">The name of the key to use for decryption.</param>
        /// <returns>The decrypted plaintext string.</returns>
        [Obsolete("This method is obsolete. Use DecryptAsync instead to avoid blocking the calling thread.")]
        public static string Decrypt(string encryptedString, string keyName) =>
            Decrypt(encryptedString, keyName, keyName, keyName);

        /// <summary>
        /// Asynchronously encrypts a plaintext string using three distinct keys for Twofish, Serpent, and AES encryption algorithms.
        /// </summary>
        /// <param name="decryptedString">The plaintext string to be encrypted.</param>
        /// <param name="twofishKeyName">The name of the Twofish key.</param>
        /// <param name="serpentKeyName">The name of the Serpent key.</param>
        /// <param name="aesKeyName">The name of the AES key.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains a Base64-encoded string representing the encrypted data.</returns>
        public static async Task<string> EncryptAsync(string decryptedString, string twofishKeyName, string serpentKeyName, string aesKeyName)
        {
            // Validate all input parameters.
            ValidateInput(decryptedString, twofishKeyName, serpentKeyName, aesKeyName);

            // Retrieve the encryption keys asynchronously from the key management provider
            var manager = await KeyFactory.InstanceAsync().ConfigureAwait(false);
            byte[] twofishKey = await manager.GetEncryptionKeyAsync(twofishKeyName).ConfigureAwait(false);
            byte[] serpentKey = await manager.GetEncryptionKeyAsync(serpentKeyName).ConfigureAwait(false);
            byte[] aesKey = await manager.GetEncryptionKeyAsync(aesKeyName).ConfigureAwait(false);

            // Initialize the encryptor with the retrieved keys.
            var encryptor = new DataEncryptor(twofishKey, serpentKey, aesKey);
            // Convert the plaintext string to a byte array.
            byte[] decryptedBytes = Encoding.UTF8.GetBytes(decryptedString);
            // Encrypt the byte array using the encryptor.
            byte[] encryptedBytes = encryptor.Encrypt(decryptedBytes);
            // Return the encrypted data as a Base64 encoded string.
            return Convert.ToBase64String(encryptedBytes);
        }

        /// <summary>
        /// Asynchronously encrypts a plaintext string using a single key for all encryption layers.
        /// </summary>
        /// <param name="decryptedString">The plaintext string to encrypt.</param>
        /// <param name="keyName">The key name used for Twofish, Serpent, and AES.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the encrypted Base64-encoded string.</returns>
        public static Task<string> EncryptAsync(string decryptedString, string keyName) =>
            EncryptAsync(decryptedString, keyName, keyName, keyName);

        /// <summary>
        /// Asynchronously decrypts a Base64-encoded string using three distinct keys for Twofish, Serpent, and AES encryption algorithms.
        /// </summary>
        /// <param name="encryptedString">The Base64-encoded string to be decrypted.</param>
        /// <param name="twofishKeyName">The name of the Twofish key.</param>
        /// <param name="serpentKeyName">The name of the Serpent key.</param>
        /// <param name="aesKeyName">The name of the AES key.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the decrypted plaintext string.</returns>
        public static async Task<string> DecryptAsync(string encryptedString, string twofishKeyName, string serpentKeyName, string aesKeyName)
        {
            // Validate all input parameters.
            ValidateInput(encryptedString, twofishKeyName, serpentKeyName, aesKeyName);

            // Retrieve all decryption key versions.
            var manager = await KeyFactory.InstanceAsync().ConfigureAwait(false);
            var twofishKeys = await manager.GetDecryptionKeysAsync(twofishKeyName).ConfigureAwait(false);
            var serpentKeys = await manager.GetDecryptionKeysAsync(serpentKeyName).ConfigureAwait(false);
            var aesKeys = await manager.GetDecryptionKeysAsync(aesKeyName).ConfigureAwait(false);

            // Convert the Base64 encoded string to a byte array.
            byte[] encryptedBytes = Convert.FromBase64String(encryptedString);

            foreach (var tf in twofishKeys)
            {
                foreach (var sp in serpentKeys)
                {
                    foreach (var aes in aesKeys)
                    {
                        try
                        {
                            // Initialize the decryptor with the retrieved keys.
                            var decryptor = new DataDecryptor(tf, sp, aes);
                            // Decrypt the byte array using the decryptor.
                            var decryptedBytes = decryptor.Decrypt(encryptedBytes);
                            // Return the decrypted data as a plaintext string.
                            return Encoding.UTF8.GetString(decryptedBytes);
                        }
                        catch
                        {
                            // Ignore failed attempts and try the next combination
                        }
                    }
                }
            }

            throw new CryptographicException("Decryption failed with all available key combinations.");
        }

        /// <summary>
        /// Asynchronously decrypts a Base64-encoded string using the same key for all encryption layers.
        /// </summary>
        /// <param name="encryptedString">The Base64-encoded string to decrypt.</param>
        /// <param name="keyName">The name of the key used for all layers.</param>
        /// <returns>A task that represents the asynchronous operation. The task result contains the decrypted plaintext string.</returns>
        public static Task<string> DecryptAsync(string encryptedString, string keyName) =>
            DecryptAsync(encryptedString, keyName, keyName, keyName);

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

                if (!Regex.IsMatch(keyName, @"^[a-zA-Z][a-zA-Z0-9\-]{0,126}$"))
                    throw new ArgumentException("Invalid key name. A key name can be 1-127 characters, starting with a letter, containing only 0-9, a-z, A-Z, and -", nameof(keyName));
            }
        }
    }
}