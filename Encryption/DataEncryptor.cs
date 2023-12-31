﻿using Reina.Cryptography.Interfaces;
using System;
using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Security;

namespace Reina.Cryptography.Encryption
{
    /// <summary>
    /// Implements encryption operations using a cascading triple-layered technique with Twofish, Serpent, and AES algorithms.
    /// This class provides a high level of security by encrypting data in multiple stages.
    /// </summary>
    internal class DataEncryptor : IEncryptor
    {
        private readonly byte[] _twofishKey;
        private readonly byte[] _serpentKey;
        private readonly byte[] _aesKey;

        /// <summary>
        /// Initializes a new instance of the <see cref="DataEncryptor"/> class with the specified keys for Twofish, Serpent, and AES.
        /// </summary>
        /// <param name="twofishKey">The 256-bit Twofish key for encryption.</param>
        /// <param name="serpentKey">The 256-bit Serpent key for encryption.</param>
        /// <param name="aesKey">The 256-bit AES key for encryption.</param>
        /// <exception cref="ArgumentNullException">Thrown when any key is null.</exception>
        /// <exception cref="ArgumentException">Thrown when any key is not 256 bits in length.</exception>
        public DataEncryptor(byte[] twofishKey, byte[] serpentKey, byte[] aesKey)
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
        /// Encrypts the specified plaintext data using a layered approach with Twofish, Serpent, and AES algorithms.
        /// </summary>
        /// <param name="decryptedBytes">The plaintext data to encrypt.</param>
        /// <returns>The encrypted data as a byte array, including the initialization vectors (IVs) for each encryption stage.</returns>
        /// <exception cref="ArgumentNullException">Thrown when the plaintext data is null.</exception>
        public byte[] Encrypt(byte[] decryptedBytes)
        {
            if (decryptedBytes == null)
                throw new ArgumentNullException(nameof(decryptedBytes), "Plaintext data to encrypt cannot be null.");

            // Perform encryption in the order of Twofish, Serpent, and then AES.
            var twofishEncrypted = EncryptWithTwofish(decryptedBytes);
            var serpentEncrypted = EncryptWithSerpent(twofishEncrypted);
            var aesEncrypted = EncryptWithAES(serpentEncrypted);

            return aesEncrypted;
        }

        /// <summary>
        /// Encrypts the data using the Twofish algorithm in CBC mode with PKCS7 padding.
        /// </summary>
        /// <param name="data">The plaintext data to encrypt.</param>
        /// <returns>The encrypted data as a byte array, including the initialization vector (IV).</returns>
        private byte[] EncryptWithTwofish(byte[] data)
        {
            // Initialize Twofish engine and cipher parameters.
            var twofishEngine = new TwofishEngine();
            var blockCipher = new CbcBlockCipher(twofishEngine);
            var cipher = new PaddedBufferedBlockCipher(blockCipher, new Pkcs7Padding());
            var keyParam = new KeyParameter(_twofishKey);
            var random = new SecureRandom();
            var ivTwofish = new byte[twofishEngine.GetBlockSize()];
            random.NextBytes(ivTwofish);
            var keyWithIv = new ParametersWithIV(keyParam, ivTwofish);
            cipher.Init(true, keyWithIv);

            // Perform encryption.
            var output = new byte[cipher.GetOutputSize(data.Length)];
            var len = cipher.ProcessBytes(data, 0, data.Length, output, 0);
            cipher.DoFinal(output, len);

            // Prepend IV to the encrypted data.
            var twofishEncrypted = new byte[ivTwofish.Length + output.Length];
            Array.Copy(ivTwofish, 0, twofishEncrypted, 0, ivTwofish.Length);
            Array.Copy(output, 0, twofishEncrypted, ivTwofish.Length, output.Length);

            return twofishEncrypted;
        }

        /// <summary>
        /// Encrypts the data using the Serpent algorithm in CBC mode with PKCS7 padding.
        /// </summary>
        /// <param name="data">The data to encrypt, typically already encrypted by another algorithm.</param>
        /// <returns>The encrypted data as a byte array, including the initialization vector (IV).</returns>
        private byte[] EncryptWithSerpent(byte[] data)
        {
            // Initialize Serpent engine and cipher parameters.
            var serpentEngine = new SerpentEngine();
            var serpentBlockCipher = new CbcBlockCipher(serpentEngine);
            var serpentCipher = new PaddedBufferedBlockCipher(serpentBlockCipher, new Pkcs7Padding());
            var serpentKeyParam = new KeyParameter(_serpentKey);
            var serpentRandom = new SecureRandom();
            var ivSerpent = new byte[serpentEngine.GetBlockSize()];
            serpentRandom.NextBytes(ivSerpent);
            var serpentKeyWithIv = new ParametersWithIV(serpentKeyParam, ivSerpent);
            serpentCipher.Init(true, serpentKeyWithIv);

            // Perform encryption.
            var serpentOutput = new byte[serpentCipher.GetOutputSize(data.Length)];
            var serpentLen = serpentCipher.ProcessBytes(data, 0, data.Length, serpentOutput, 0);
            serpentCipher.DoFinal(serpentOutput, serpentLen);

            // Prepend IV to the encrypted data.
            var serpentEncrypted = new byte[ivSerpent.Length + serpentOutput.Length];
            Array.Copy(ivSerpent, 0, serpentEncrypted, 0, ivSerpent.Length);
            Array.Copy(serpentOutput, 0, serpentEncrypted, ivSerpent.Length, serpentOutput.Length);

            return serpentEncrypted;
        }

        /// <summary>
        /// Encrypts the data using the AES algorithm in its default mode with an auto-generated IV.
        /// </summary>
        /// <param name="data">The data to encrypt, typically already encrypted by other algorithms.</param>
        /// <returns>The encrypted data as a byte array, including the initialization vector (IV).</returns>
        private byte[] EncryptWithAES(byte[] data)
        {
            // Initialize AES engine.
            using var aes = Aes.Create();
            aes.Key = _aesKey;
            aes.GenerateIV();

            // Perform encryption, writing the IV followed by the encrypted data.
            using var memoryStream = new MemoryStream();
            memoryStream.Write(aes.IV, 0, aes.IV.Length);

            using var cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
            cryptoStream.Write(data, 0, data.Length);
            cryptoStream.FlushFinalBlock();

            return memoryStream.ToArray();
        }
    }
}