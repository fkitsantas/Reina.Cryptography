using Reina.Cryptography.Encryption;
using Reina.Cryptography.Decryption;
using Reina.Cryptography.KeyManagement;
using System;
using System.Text;
using System.Threading.Tasks;

namespace Reina.Cryptography
{
    public static class Core
    {
        public static async Task<string> Encrypt(string decryptedString, string keyName)
        {
            if (string.IsNullOrEmpty(decryptedString))
            {
                throw new ArgumentNullException(nameof(decryptedString), "Input string cannot be null or empty.");
            }
            if (string.IsNullOrEmpty(keyName))
            {
                throw new ArgumentNullException(nameof(keyName), "Key name cannot be null or empty.");
            }
            if (!System.Text.RegularExpressions.Regex.IsMatch(keyName, @"^[a-zA-Z][a-zA-Z0-9\-]{0,126}$"))
            {
                throw new ArgumentException("Invalid key name. The name must be a 1-127 character string, starting with a letter and containing only 0-9, a-z, A-Z, and -.", nameof(keyName));
            }

            byte[] encryptionKey = await AzureKVKeyManager.Instance.GetEncryptionKeyAsync(keyName);
            var dataEncryptor = new DataEncryptor(encryptionKey);
            byte[] decryptedBytes = Encoding.UTF8.GetBytes(decryptedString);
            byte[] encryptedBytes = await dataEncryptor.EncryptAsync(decryptedBytes);
            return Convert.ToBase64String(encryptedBytes);
        }

        public static async Task<string> Decrypt(string encryptedString, string keyName)
        {
            if (string.IsNullOrEmpty(encryptedString))
            {
                throw new ArgumentNullException(nameof(encryptedString), "Encrypted string cannot be null or empty.");
            }
            if (string.IsNullOrEmpty(keyName))
            {
                throw new ArgumentNullException(nameof(keyName), "Key name cannot be null or empty.");
            }
            if (!System.Text.RegularExpressions.Regex.IsMatch(keyName, @"^[a-zA-Z][a-zA-Z0-9\-]{0,126}$"))
            {
                throw new ArgumentException("Invalid key name. The name must be a 1-127 character string, starting with a letter and containing only 0-9, a-z, A-Z, and -.", nameof(keyName));
            }

            byte[] encryptionKey = await AzureKVKeyManager.Instance.GetEncryptionKeyAsync(keyName);
            var dataDecryptor = new DataDecryptor(encryptionKey);
            byte[] encryptedBytes = Convert.FromBase64String(encryptedString);
            byte[] decryptedBytes = await dataDecryptor.DecryptAsync(encryptedBytes);
            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}
