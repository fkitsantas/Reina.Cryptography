using Reina.Cryptography.Interfaces;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Security;

namespace Reina.Cryptography.Decryption
{
    internal class DataDecryptor : IDecryptor
    {
        private readonly byte[] _key;

        public DataDecryptor(byte[] key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key), "Key cannot be null.");
            }

            if (key.Length != 32) // 32 bytes = 256 bits
            {
                throw new ArgumentException("Invalid key size. Expected a 256-bit key.", nameof(key));
            }

            _key = key;
        }

        public async Task<byte[]> DecryptAsync(byte[] encryptedBytes)
        {
            return await Task.Run(() =>
            {
                try
                {
                    // AES Decryption
                    byte[] aesDecrypted;
                    using (var aes = Aes.Create())
                    {
                        int ivLengthAes = aes.BlockSize / 8;
                        if (encryptedBytes.Length < ivLengthAes)
                        {
                            throw new ArgumentException("The encrypted data is too short to contain the AES IV.", nameof(encryptedBytes));
                        }

                        var ivAes = new byte[ivLengthAes];
                        Array.Copy(encryptedBytes, ivAes, ivLengthAes);

                        aes.Key = _key;
                        aes.IV = ivAes;

                        using (var memoryStream = new MemoryStream(encryptedBytes, ivLengthAes, encryptedBytes.Length - ivLengthAes))
                        using (var cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                        using (var streamReader = new MemoryStream())
                        {
                            cryptoStream.CopyTo(streamReader);
                            aesDecrypted = streamReader.ToArray();
                        }
                    }

                    // Serpent Decryption
                    var serpentEngine = new SerpentEngine();
                    var serpentBlockCipher = new CbcBlockCipher(serpentEngine);
                    var serpentCipher = new PaddedBufferedBlockCipher(serpentBlockCipher, new Pkcs7Padding());

                    int ivLengthSerpent = serpentEngine.GetBlockSize();
                    if (aesDecrypted.Length < ivLengthSerpent)
                    {
                        throw new ArgumentException("The decrypted data is too short to contain the Serpent IV.");
                    }

                    var ivSerpent = new byte[ivLengthSerpent];
                    Array.Copy(aesDecrypted, ivSerpent, ivLengthSerpent);

                    var serpentKeyParam = new KeyParameter(_key);
                    var serpentKeyWithIv = new ParametersWithIV(serpentKeyParam, ivSerpent);
                    serpentCipher.Init(false, serpentKeyWithIv);

                    var serpentInput = new byte[aesDecrypted.Length - ivLengthSerpent];
                    Array.Copy(aesDecrypted, ivLengthSerpent, serpentInput, 0, serpentInput.Length);

                    var serpentOutput = new byte[serpentCipher.GetOutputSize(serpentInput.Length)];
                    var serpentLen = serpentCipher.ProcessBytes(serpentInput, 0, serpentInput.Length, serpentOutput, 0);
                    int serpentFinalLen = serpentCipher.DoFinal(serpentOutput, serpentLen);

                    var serpentDecrypted = new byte[serpentLen + serpentFinalLen];
                    Array.Copy(serpentOutput, serpentDecrypted, serpentLen + serpentFinalLen);

                    // Twofish Decryption
                    var twofishEngine = new TwofishEngine();
                    var blockCipher = new CbcBlockCipher(twofishEngine);
                    var cipher = new PaddedBufferedBlockCipher(blockCipher, new Pkcs7Padding());

                    int ivLengthTwofish = twofishEngine.GetBlockSize();
                    if (serpentDecrypted.Length < ivLengthTwofish)
                    {
                        throw new ArgumentException("The decrypted data is too short to contain the Twofish IV.");
                    }

                    var ivTwofish = new byte[ivLengthTwofish];
                    Array.Copy(serpentDecrypted, ivTwofish, ivLengthTwofish);

                    var keyParam = new KeyParameter(_key);
                    var keyWithIv = new ParametersWithIV(keyParam, ivTwofish);
                    cipher.Init(false, keyWithIv);

                    var input = new byte[serpentDecrypted.Length - ivLengthTwofish];
                    Array.Copy(serpentDecrypted, ivLengthTwofish, input, 0, input.Length);

                    var output = new byte[cipher.GetOutputSize(input.Length)];
                    var len = cipher.ProcessBytes(input, 0, input.Length, output, 0);
                    int finalLen = cipher.DoFinal(output, len);

                    var twofishDecrypted = new byte[len + finalLen];
                    Array.Copy(output, twofishDecrypted, len + finalLen);

                    return twofishDecrypted;
                }
                catch (CryptographicException ce)
                {
                    if (ce.Message.Contains("Padding is invalid"))
                    {
                        throw new CryptographicException("The provided key or IV is incorrect, or the encrypted data has been tampered with or corrupted.");
                    }
                    throw new CryptographicException("A cryptographic error occurred during decryption. Please ensure the encrypted data, key, and IV are valid.", ce);
                }
                catch (ArgumentException ae)
                {
                    throw new ArgumentException("The encrypted data provided is invalid or corrupted.", ae);
                }
                catch (Exception ex)
                {
                    throw new Exception("An unexpected error occurred during decryption.", ex);
                }
           });
                
        }
    }
}
