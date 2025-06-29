using Reina.Cryptography.Interfaces;
using System;
using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Security;

namespace Reina.Cryptography.Decryption
{
    /// <summary>
    /// Implements decryption operations using a cascading triple-layered technique with Twofish, Serpent, and AES algorithms.
    /// This class provides a high level of security by decrypting data in multiple stages.
    /// </summary>
    internal class DataDecryptor : IDecryptor
    {
        private readonly byte[] _twofishKey;
        private readonly byte[] _serpentKey;
        private readonly byte[] _aesKey;

        /// <summary>
        /// Initializes a new instance of the <see cref="DataDecryptor"/> class with the specified keys for Twofish, Serpent, and AES.
        /// </summary>
        /// <param name="twofishKey">The 256-bit Twofish key for decryption.</param>
        /// <param name="serpentKey">The 256-bit Serpent key for decryption.</param>
        /// <param name="aesKey">The 256-bit AES key for decryption.</param>
        /// <exception cref="ArgumentNullException">Thrown when any key is null.</exception>
        /// <exception cref="ArgumentException">Thrown when any key is not 256 bits in length.</exception>
        public DataDecryptor(byte[] twofishKey, byte[] serpentKey, byte[] aesKey)
        {
            _twofishKey = twofishKey ?? throw new ArgumentNullException(nameof(twofishKey), "Twofish key cannot be null.");
            _serpentKey = serpentKey ?? throw new ArgumentNullException(nameof(serpentKey), "Serpent key cannot be null.");
            _aesKey = aesKey ?? throw new ArgumentNullException(nameof(aesKey), "AES key cannot be null.");

            ValidateKey(_twofishKey, nameof(twofishKey));
            ValidateKey(_serpentKey, nameof(serpentKey));
            ValidateKey(_aesKey, nameof(aesKey));
        }

        /// <summary>
        /// Validates the length of the provided cryptographic key.
        /// </summary>
        /// <param name="key">The cryptographic key to validate.</param>
        /// <param name="whichKey">The name of the key for error messaging purposes.</param>
        /// <exception cref="ArgumentException">Thrown when the key is not 256 bits in length.</exception>
        private void ValidateKey(byte[] key, string whichKey)
        {
            if (key.Length != 32)
                throw new ArgumentException("Invalid key size. Expected a 256-bit key.", whichKey);
        }

        /// <summary>
        /// Decrypts the specified encrypted data using a layered approach with AES, Serpent, and Twofish algorithms.
        /// </summary>
        /// <param name="encryptedBytes">The encrypted data to decrypt.</param>
        /// <returns>The decrypted data as a byte array.</returns>
        /// <exception cref="ArgumentNullException">Thrown when the encrypted data is null.</exception>
        /// <exception cref="CryptographicException">Thrown when decryption fails due to invalid padding or other cryptographic issues.</exception>
        /// <exception cref="ArgumentException">Thrown when the encrypted data is too short or corrupted.</exception>
        public byte[] Decrypt(byte[] encryptedBytes)
        {
            if (encryptedBytes == null)
                throw new ArgumentNullException(nameof(encryptedBytes), "Encrypted data cannot be null.");

            // Attempt to decrypt the data in a try-catch block to handle potential cryptographic exceptions.
            try
            {
                // Perform decryption in reverse order of encryption: first AES, then Serpent, and finally Twofish.
                byte[] aesDecrypted = DecryptWithAES(encryptedBytes);
                byte[] serpentDecrypted = DecryptWithSerpent(aesDecrypted);
                byte[] twofishDecrypted = DecryptWithTwofish(serpentDecrypted);

                return twofishDecrypted;
            }
            catch (CryptographicException ce)
            {
                // Provide more context to the cryptographic exception for better error diagnosis.
                throw new CryptographicException("Decryption failed: " + ce.Message, ce);
            }
            catch (ArgumentException ae)
            {
                // Re-throw the argument exception with additional context.
                throw new ArgumentException("Decryption failed: " + ae.Message, ae);
            }
            catch (Exception ex)
            {
                // General exception handling as a fallback to catch any other unexpected errors.
                throw new Exception("Decryption failed: An unexpected error occurred.", ex);
            }
        }

        /// <summary>
        /// Decrypts the data using the AES algorithm in CBC mode with PKCS7 padding.
        /// </summary>
        /// <param name="encryptedBytes">The encrypted data with the AES IV prepended.</param>
        /// <returns>The decrypted data as a byte array.</returns>
        /// <exception cref="ArgumentException">Thrown when the encrypted data does not contain a valid AES IV.</exception>
        private byte[] DecryptWithAES(byte[] encryptedBytes)
        {
            using var aes = Aes.Create();
            {
                int ivLengthAes = aes.BlockSize / 8;
                if (encryptedBytes.Length < ivLengthAes)
                    throw new ArgumentException("The encrypted data is too short to contain the AES IV.", nameof(encryptedBytes));

                // Extract the IV from the beginning of the encrypted data.
                var ivAes = new byte[ivLengthAes];
                Array.Copy(encryptedBytes, ivAes, ivLengthAes);

                aes.Key = _aesKey;
                aes.IV = ivAes;

                // Decrypt the remaining encrypted data after the IV.
                using var memoryStream = new MemoryStream(encryptedBytes, ivLengthAes, encryptedBytes.Length - ivLengthAes);
                using var cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
                using var streamReader = new MemoryStream();
                cryptoStream.CopyTo(streamReader);
                return streamReader.ToArray();
            }
        }

        /// <summary>
        /// Decrypts the data using the Serpent algorithm in CBC mode with PKCS7 padding.
        /// </summary>
        /// <param name="encryptedBytes">The encrypted data with the Serpent IV prepended.</param>
        /// <returns>The decrypted data as a byte array.</returns>
        /// <exception cref="ArgumentException">Thrown when the encrypted data does not contain a valid Serpent IV.</exception>
        private byte[] DecryptWithSerpent(byte[] encryptedBytes)
        {
            // Initialize Serpent engine and cipher parameters.
            var serpentEngine = new SerpentEngine();
            int ivLengthSerpent = serpentEngine.GetBlockSize();
            if (encryptedBytes.Length < ivLengthSerpent)
                throw new ArgumentException("The decrypted data is too short to contain the Serpent IV.");

            // Extract the IV from the beginning of the encrypted data.
            var ivSerpent = new byte[ivLengthSerpent];
            Array.Copy(encryptedBytes, ivSerpent, ivLengthSerpent);

            var serpentCipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(serpentEngine), new Pkcs7Padding());
            var serpentKeyParam = new KeyParameter(_serpentKey);
            var serpentKeyWithIv = new ParametersWithIV(serpentKeyParam, ivSerpent);
            serpentCipher.Init(false, serpentKeyWithIv);

            // Decrypt the remaining encrypted data after the IV.
            var serpentInput = new byte[encryptedBytes.Length - ivLengthSerpent];
            Array.Copy(encryptedBytes, ivLengthSerpent, serpentInput, 0, serpentInput.Length);

            return ProcessCipher(serpentCipher, serpentInput);
        }

        /// <summary>
        /// Decrypts the data using the Twofish algorithm in CBC mode with PKCS7 padding.
        /// </summary>
        /// <param name="encryptedBytes">The encrypted data with the Twofish IV prepended.</param>
        /// <returns>The decrypted data as a byte array.</returns>
        /// <exception cref="ArgumentException">Thrown when the encrypted data does not contain a valid Twofish IV.</exception>
        private byte[] DecryptWithTwofish(byte[] encryptedBytes)
        {
            // Initialize Twofish engine and cipher parameters.
            var twofishEngine = new TwofishEngine();
            int ivLengthTwofish = twofishEngine.GetBlockSize();
            if (encryptedBytes.Length < ivLengthTwofish)
                throw new ArgumentException("The decrypted data is too short to contain the Twofish IV.");

            // Extract the IV from the beginning of the encrypted data.
            var ivTwofish = new byte[ivLengthTwofish];
            Array.Copy(encryptedBytes, ivTwofish, ivLengthTwofish);

            var twofishCipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(twofishEngine), new Pkcs7Padding());
            var keyParam = new KeyParameter(_twofishKey);
            var keyWithIv = new ParametersWithIV(keyParam, ivTwofish);
            twofishCipher.Init(false, keyWithIv);

            // Decrypt the remaining encrypted data after the IV.
            var twofishInput = new byte[encryptedBytes.Length - ivLengthTwofish];
            Array.Copy(encryptedBytes, ivLengthTwofish, twofishInput, 0, twofishInput.Length);

            return ProcessCipher(twofishCipher, twofishInput);
        }

        /// <summary>
        /// Processes the cipher operation (decryption) on the given input data.
        /// </summary>
        /// <param name="cipher">The cipher to use for decryption.</param>
        /// <param name="input">The input data to decrypt.</param>
        /// <returns>The decrypted data as a byte array.</returns>
        private byte[] ProcessCipher(IBufferedCipher cipher, byte[] input)
        {
            // Calculate the size of the output buffer and perform the decryption.
            var output = new byte[cipher.GetOutputSize(input.Length)];
            var len = cipher.ProcessBytes(input, 0, input.Length, output, 0);
            len += cipher.DoFinal(output, len);

            // Trim the output to the actual length of the decrypted data.
            var decrypted = new byte[len];
            Array.Copy(output, decrypted, len);
            return decrypted;
        }
    }
}