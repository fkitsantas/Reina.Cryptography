using Reina.Cryptography.Configuration;
using Reina.Cryptography.Decryption;
using Reina.Cryptography.Encryption;
using Reina.Cryptography.KeyManagement;
using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Reina.Cryptography
{
    /// <summary>
    /// Provides core functionality for encryption and decryption of data,
    /// interfacing with a cloud-based key management provider.
    /// </summary>
public static partial class Library
    {
        #if NET8_0_OR_GREATER
        [GeneratedRegex(@"^[a-zA-Z][a-zA-Z0-9\-]{0,126}$")]
        private static partial Regex KeyNameRegex();
        #endif

        /// <summary>
        /// Lock object used to ensure thread-safe initialization.
        /// </summary>
        #if NET10_0_OR_GREATER
        private static readonly System.Threading.Lock _initLock = new();
        #else
        private static readonly object _initLock = new();
        #endif
        // IDE0090: 'new' expression can be simplified
        // (No explicit 'new' found in this snippet, but if present elsewhere, use 'new()' where possible.)
        /// <summary>
        /// Indicates whether the library has been successfully initialized.
        /// </summary>
        private static bool _initialized;

        /// <summary>
        /// Explicitly validates the library configuration. Must be called once
        /// before any encrypt or decrypt operations. Subsequent calls are
        /// no-ops. Throws <see cref="InvalidOperationException"/> if the
        /// configuration is invalid.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        /// Thrown if the configuration is invalid or cannot be validated.
        /// </exception>
        public static void Initialize()
        {
            lock (_initLock)
            {
                if (_initialized) return;
                Config.Instance.ValidateConfiguration();
                _initialized = true;
            }
        }

        // ------------------------------------------------------------------
        // Obsolete synchronous API — kept for backward compatibility only.
        // These methods can deadlock in UI / ASP.NET Framework contexts.
        // ------------------------------------------------------------------

        /// <summary>
        /// Encrypts a plaintext string using three distinct keys for Twofish,
        /// Serpent, and AES encryption algorithms. This method is synchronous
        /// and blocks the calling thread. It can deadlock in UI or ASP.NET
        /// Framework contexts.
        /// </summary>
        /// <param name="decryptedString">The plaintext string to encrypt.</param>
        /// <param name="twofishKeyName">The name of the Twofish key.</param>
        /// <param name="serpentKeyName">The name of the Serpent key.</param>
        /// <param name="aesKeyName">The name of the AES key.</param>
        /// <returns>A Base64-encoded string representing the encrypted data.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown if <paramref name="decryptedString"/> or any key name is null or empty.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown if any key name does not match the required format.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// Thrown if <see cref="Initialize"/> has not been called.
        /// </exception>
        [Obsolete("Use EncryptAsync instead to avoid blocking the calling thread.")]
        public static string Encrypt(
            string decryptedString,
            string twofishKeyName,
            string serpentKeyName,
            string aesKeyName) =>
            EncryptAsync(decryptedString, twofishKeyName, serpentKeyName, aesKeyName)
                .GetAwaiter().GetResult();

        /// <summary>
        /// Encrypts a plaintext string using a single key for all three
        /// encryption layers (Twofish, Serpent, and AES). This method is
        /// synchronous and blocks the calling thread. It can deadlock in UI
        /// or ASP.NET Framework contexts.
        /// </summary>
        /// <param name="decryptedString">The plaintext string to encrypt.</param>
        /// <param name="keyName">
        /// The name of the key used for all three encryption layers.
        /// </param>
        /// <returns>A Base64-encoded string representing the encrypted data.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown if <paramref name="decryptedString"/> or <paramref name="keyName"/>
        /// is null or empty.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown if <paramref name="keyName"/> does not match the required format.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// Thrown if <see cref="Initialize"/> has not been called.
        /// </exception>
        [Obsolete("Use EncryptAsync instead to avoid blocking the calling thread.")]
        public static string Encrypt(string decryptedString, string keyName) =>
            Encrypt(decryptedString, keyName, keyName, keyName);

        /// <summary>
        /// Decrypts a Base64-encoded string using three distinct keys for
        /// Twofish, Serpent, and AES encryption algorithms. This method is
        /// synchronous and blocks the calling thread. It can deadlock in UI
        /// or ASP.NET Framework contexts.
        /// </summary>
        /// <param name="encryptedString">The Base64-encoded string to decrypt.</param>
        /// <param name="twofishKeyName">The name of the Twofish key.</param>
        /// <param name="serpentKeyName">The name of the Serpent key.</param>
        /// <param name="aesKeyName">The name of the AES key.</param>
        /// <returns>The decrypted plaintext string.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown if <paramref name="encryptedString"/> or any key name is null or empty.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown if any key name does not match the required format.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// Thrown if <see cref="Initialize"/> has not been called.
        /// </exception>
        /// <exception cref="CryptographicException">
        /// Thrown if decryption fails with all available key combinations.
        /// </exception>
        [Obsolete("Use DecryptAsync instead to avoid blocking the calling thread.")]
        public static string Decrypt(
            string encryptedString,
            string twofishKeyName,
            string serpentKeyName,
            string aesKeyName) =>
            DecryptAsync(encryptedString, twofishKeyName, serpentKeyName, aesKeyName)
                .GetAwaiter().GetResult();

        /// <summary>
        /// Decrypts a Base64-encoded string using a single key for all three
        /// encryption layers (Twofish, Serpent, and AES). This method is
        /// synchronous and blocks the calling thread. It can deadlock in UI
        /// or ASP.NET Framework contexts.
        /// </summary>
        /// <param name="encryptedString">The Base64-encoded string to decrypt.</param>
        /// <param name="keyName">
        /// The name of the key used for all three encryption layers.
        /// </param>
        /// <returns>The decrypted plaintext string.</returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown if <paramref name="encryptedString"/> or <paramref name="keyName"/>
        /// is null or empty.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown if <paramref name="keyName"/> does not match the required format.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// Thrown if <see cref="Initialize"/> has not been called.
        /// </exception>
        /// <exception cref="CryptographicException">
        /// Thrown if decryption fails with all available key combinations.
        /// </exception>
        [Obsolete("Use DecryptAsync instead to avoid blocking the calling thread.")]
        public static string Decrypt(string encryptedString, string keyName) =>
            Decrypt(encryptedString, keyName, keyName, keyName);

        // ------------------------------------------------------------------
        // Async API
        // ------------------------------------------------------------------

        /// <summary>
        /// Asynchronously encrypts a plaintext string using three distinct keys
        /// for Twofish, Serpent, and AES encryption algorithms. Keys are
        /// retrieved from the cloud-based key management provider and zeroed
        /// from memory immediately after use.
        /// </summary>
        /// <param name="decryptedString">The plaintext string to encrypt.</param>
        /// <param name="twofishKeyName">The name of the Twofish key.</param>
        /// <param name="serpentKeyName">The name of the Serpent key.</param>
        /// <param name="aesKeyName">The name of the AES key.</param>
        /// <param name="cancellationToken">
        /// A token that can be used to cancel the operation before it completes.
        /// Defaults to <see cref="CancellationToken.None"/> if not provided.
        /// </param>
        /// <returns>
        /// A task representing the asynchronous operation. The result is a
        /// Base64-encoded string representing the encrypted data.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown if <paramref name="decryptedString"/> or any key name is null or empty.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown if any key name does not match the required format.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// Thrown if <see cref="Initialize"/> has not been called.
        /// </exception>
        /// <exception cref="OperationCanceledException">
        /// Thrown if the operation is cancelled via <paramref name="cancellationToken"/>.
        /// </exception>
        public static async Task<string> EncryptAsync(
            string decryptedString,
            string twofishKeyName,
            string serpentKeyName,
            string aesKeyName,
            CancellationToken cancellationToken = default)
        {
            EnsureInitialized();
            ValidateInput(decryptedString, twofishKeyName, serpentKeyName, aesKeyName);

            var manager = await KeyFactory.InstanceAsync().ConfigureAwait(false);

            byte[]? twofishKey = null;
            byte[]? serpentKey = null;
            byte[]? aesKey = null;

            try
            {
                cancellationToken.ThrowIfCancellationRequested();

                // Retrieve each encryption key from the key management provider.
                twofishKey = await manager.GetEncryptionKeyAsync(twofishKeyName).ConfigureAwait(false);
                serpentKey = await manager.GetEncryptionKeyAsync(serpentKeyName).ConfigureAwait(false);
                aesKey = await manager.GetEncryptionKeyAsync(aesKeyName).ConfigureAwait(false);

                cancellationToken.ThrowIfCancellationRequested();

                // Encrypt the plaintext bytes through the triple-layer encryptor.
                var encryptor = new DataEncryptor(twofishKey, serpentKey, aesKey);
                byte[] plainBytes = Encoding.UTF8.GetBytes(decryptedString);
                byte[] cipherBytes = encryptor.Encrypt(plainBytes);

                return Convert.ToBase64String(cipherBytes);
            }
            finally
            {
                // Zero all key material from memory regardless of success or failure
                // to prevent sensitive data lingering on the managed heap.
                if (twofishKey != null) ZeroMemory(twofishKey);
                if (serpentKey != null) ZeroMemory(serpentKey);
                if (aesKey != null) ZeroMemory(aesKey);
            }
        }

        /// <summary>
        /// Asynchronously encrypts a plaintext string using a single key for
        /// all three encryption layers (Twofish, Serpent, and AES). Keys are
        /// retrieved from the cloud-based key management provider and zeroed
        /// from memory immediately after use.
        /// </summary>
        /// <param name="decryptedString">The plaintext string to encrypt.</param>
        /// <param name="keyName">
        /// The name of the key used for all three encryption layers.
        /// </param>
        /// <param name="cancellationToken">
        /// A token that can be used to cancel the operation before it completes.
        /// Defaults to <see cref="CancellationToken.None"/> if not provided.
        /// </param>
        /// <returns>
        /// A task representing the asynchronous operation. The result is a
        /// Base64-encoded string representing the encrypted data.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown if <paramref name="decryptedString"/> or <paramref name="keyName"/>
        /// is null or empty.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown if <paramref name="keyName"/> does not match the required format.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// Thrown if <see cref="Initialize"/> has not been called.
        /// </exception>
        /// <exception cref="OperationCanceledException">
        /// Thrown if the operation is cancelled via <paramref name="cancellationToken"/>.
        /// </exception>
        public static Task<string> EncryptAsync(
            string decryptedString,
            string keyName,
            CancellationToken cancellationToken = default) =>
            EncryptAsync(decryptedString, keyName, keyName, keyName, cancellationToken);

        /// <summary>
        /// Asynchronously decrypts a Base64-encoded string using three distinct
        /// keys for Twofish, Serpent, and AES encryption algorithms. All
        /// available versions of each key are tried in combination until
        /// decryption succeeds. All key material is zeroed from memory
        /// immediately after use.
        /// </summary>
        /// <param name="encryptedString">The Base64-encoded string to decrypt.</param>
        /// <param name="twofishKeyName">The name of the Twofish key.</param>
        /// <param name="serpentKeyName">The name of the Serpent key.</param>
        /// <param name="aesKeyName">The name of the AES key.</param>
        /// <param name="cancellationToken">
        /// A token that can be used to cancel the operation before it completes.
        /// Defaults to <see cref="CancellationToken.None"/> if not provided.
        /// </param>
        /// <returns>
        /// A task representing the asynchronous operation. The result is the
        /// decrypted plaintext string.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown if <paramref name="encryptedString"/> or any key name is null or empty.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown if any key name does not match the required format.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// Thrown if <see cref="Initialize"/> has not been called.
        /// </exception>
        /// <exception cref="OperationCanceledException">
        /// Thrown if the operation is cancelled via <paramref name="cancellationToken"/>.
        /// </exception>
        /// <exception cref="CryptographicException">
        /// Thrown if decryption fails with all available key combinations.
        /// </exception>
        public static async Task<string> DecryptAsync(
            string encryptedString,
            string twofishKeyName,
            string serpentKeyName,
            string aesKeyName,
            CancellationToken cancellationToken = default)
        {
            EnsureInitialized();
            ValidateInput(encryptedString, twofishKeyName, serpentKeyName, aesKeyName);

            var manager = await KeyFactory.InstanceAsync().ConfigureAwait(false);

            // Retrieve all available versions of each key to support key rotation.
            var twofishKeys = await manager.GetDecryptionKeysAsync(twofishKeyName).ConfigureAwait(false);
            var serpentKeys = await manager.GetDecryptionKeysAsync(serpentKeyName).ConfigureAwait(false);
            var aesKeys = await manager.GetDecryptionKeysAsync(aesKeyName).ConfigureAwait(false);

            byte[] cipherBytes = Convert.FromBase64String(encryptedString);

            try
            {
                // Try every combination of key versions to handle data encrypted
                // under a previous key rotation cycle.
                foreach (var tf in twofishKeys)
                {
                    foreach (var sp in serpentKeys)
                    {
                        foreach (var aes in aesKeys)
                        {
                            // Respect cancellation between each combination attempt.
                            cancellationToken.ThrowIfCancellationRequested();

                            try
                            {
                                var decryptor = new DataDecryptor(tf, sp, aes);
                                byte[] plainBytes = decryptor.Decrypt(cipherBytes);
                                return Encoding.UTF8.GetString(plainBytes);
                            }
                            catch (CryptographicException)
                            {
                                // This key combination did not match — try the next one.
                            }
                        }
                    }
                }
            }
            finally
            {
                // Zero all key material from memory regardless of success or failure
                // to prevent sensitive data lingering on the managed heap.
                foreach (var key in twofishKeys) ZeroMemory(key);
                foreach (var key in serpentKeys) ZeroMemory(key);
                foreach (var key in aesKeys) ZeroMemory(key);
            }

            throw new CryptographicException(
                "Decryption failed with all available key combinations.");
        }

        /// <summary>
        /// Asynchronously decrypts a Base64-encoded string using a single key
        /// for all three encryption layers (Twofish, Serpent, and AES). All
        /// available versions of the key are tried until decryption succeeds.
        /// All key material is zeroed from memory immediately after use.
        /// </summary>
        /// <param name="encryptedString">The Base64-encoded string to decrypt.</param>
        /// <param name="keyName">
        /// The name of the key used for all three encryption layers.
        /// </param>
        /// <param name="cancellationToken">
        /// A token that can be used to cancel the operation before it completes.
        /// Defaults to <see cref="CancellationToken.None"/> if not provided.
        /// </param>
        /// <returns>
        /// A task representing the asynchronous operation. The result is the
        /// decrypted plaintext string.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// Thrown if <paramref name="encryptedString"/> or <paramref name="keyName"/>
        /// is null or empty.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown if <paramref name="keyName"/> does not match the required format.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// Thrown if <see cref="Initialize"/> has not been called.
        /// </exception>
        /// <exception cref="OperationCanceledException">
        /// Thrown if the operation is cancelled via <paramref name="cancellationToken"/>.
        /// </exception>
        /// <exception cref="CryptographicException">
        /// Thrown if decryption fails with all available key combinations.
        /// </exception>
        public static Task<string> DecryptAsync(
            string encryptedString,
            string keyName,
            CancellationToken cancellationToken = default) =>
            DecryptAsync(encryptedString, keyName, keyName, keyName, cancellationToken);

        // ------------------------------------------------------------------
        // Private helpers
        // ------------------------------------------------------------------

        /// <summary>
        /// Ensures the library has been initialised by a prior call to
        /// <see cref="Initialize"/>. Throws if it has not.
        /// </summary>
        /// <exception cref="InvalidOperationException">
        /// Thrown if <see cref="Initialize"/> has not been called before
        /// attempting an encrypt or decrypt operation.
        /// </exception>
        private static void EnsureInitialized()
        {
            if (!_initialized)
                throw new InvalidOperationException(
                    "Library is not initialized. Call Library.Initialize() before use.");
        }

        /// <summary>
        /// Validates the input string and one or more key names, ensuring none
        /// are null or empty and that each key name matches the required format:
        /// 1 to 127 characters, starting with a letter, containing only
        /// letters, digits, and hyphens.
        /// </summary>
        /// <param name="input">The input string to validate.</param>
        /// <param name="keyNames">One or more key names to validate.</param>
        /// <exception cref="ArgumentNullException">
        /// Thrown if <paramref name="input"/> or any element of
        /// <paramref name="keyNames"/> is null or empty.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown if any element of <paramref name="keyNames"/> does not match
        /// the required pattern.
        /// </exception>
        private static void ValidateInput(string input, params string[] keyNames)
        {
            if (string.IsNullOrEmpty(input))
                throw new ArgumentNullException(nameof(input), "Input cannot be null or empty.");

            foreach (var keyName in keyNames)
            {
                if (string.IsNullOrEmpty(keyName))
                    throw new ArgumentNullException(nameof(keyNames), "Key name cannot be null or empty.");

                if (!Regex.IsMatch(keyName, @"^[a-zA-Z][a-zA-Z0-9\-]{0,126}$"))
#if NET8_0_OR_GREATER
                if (!KeyNameRegex().IsMatch(keyName))
                    throw new ArgumentException(
                        "Invalid key name. Must be 1-127 characters, start with a letter, " +
                        "and contain only 0-9, a-z, A-Z, and -", nameof(keyNames));
#else
                if (!Regex.IsMatch(keyName, @"^[a-zA-Z][a-zA-Z0-9\-]{0,126}$"))
                    throw new ArgumentException(
                        "Invalid key name. Must be 1-127 characters, start with a letter, " +
                        "and contain only 0-9, a-z, A-Z, and -", nameof(keyNames));
#endif
            }
        }

        /// <summary>
        /// Overwrites a key buffer with zeros to remove sensitive key material
        /// from managed memory. Safe to call with a null array — no action is
        /// taken in that case.
        /// </summary>
        /// <param name="key">
        /// The byte array to zero. If null, this method is a no-op.
        /// </param>
        private static void ZeroMemory(byte[] key)
        {
#if NET10_0_OR_GREATER
            if (key != null)
                CryptographicOperations.ZeroMemory(key);
#else
            if (key != null)
                Array.Clear(key, 0, key.Length);
#endif
        }
    }
}