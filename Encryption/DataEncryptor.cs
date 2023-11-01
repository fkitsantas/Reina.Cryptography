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

namespace Reina.Cryptography.Encryption
{
    internal class DataEncryptor : IEncryptor
    {
        private readonly byte[] _key;

        public DataEncryptor(byte[] key)
        {
            _key = key;
        }

        public async Task<byte[]> EncryptAsync(byte[] decryptedBytes)
        {
            return await Task.Run(() =>
            {
                byte[] twofishEncrypted;
                var twofishEngine = new TwofishEngine();
                var blockCipher = new CbcBlockCipher(twofishEngine);

                var cipher = new PaddedBufferedBlockCipher(blockCipher, new Pkcs7Padding());

                var keyParam = new KeyParameter(_key);
                var random = new SecureRandom();
                var ivTwofish = new byte[twofishEngine.GetBlockSize()];
                random.NextBytes(ivTwofish);

                var keyWithIv = new ParametersWithIV(keyParam, ivTwofish);
                cipher.Init(true, keyWithIv);

                var output = new byte[cipher.GetOutputSize(decryptedBytes.Length)];
                var len = cipher.ProcessBytes(decryptedBytes, 0, decryptedBytes.Length, output, 0);
                cipher.DoFinal(output, len);

                twofishEncrypted = new byte[ivTwofish.Length + output.Length];
                Array.Copy(ivTwofish, 0, twofishEncrypted, 0, ivTwofish.Length);
                Array.Copy(output, 0, twofishEncrypted, ivTwofish.Length, output.Length);

                // Serpent Encryption
                byte[] serpentEncrypted;
                var serpentEngine = new SerpentEngine();
                var serpentBlockCipher = new CbcBlockCipher(serpentEngine);
                var serpentCipher = new PaddedBufferedBlockCipher(serpentBlockCipher, new Pkcs7Padding());

                var serpentKeyParam = new KeyParameter(_key);
                var serpentRandom = new SecureRandom();
                var ivSerpent = new byte[serpentEngine.GetBlockSize()];
                serpentRandom.NextBytes(ivSerpent);

                var serpentKeyWithIv = new ParametersWithIV(serpentKeyParam, ivSerpent);
                serpentCipher.Init(true, serpentKeyWithIv);

                var serpentOutput = new byte[serpentCipher.GetOutputSize(twofishEncrypted.Length)];
                var serpentLen = serpentCipher.ProcessBytes(twofishEncrypted, 0, twofishEncrypted.Length, serpentOutput, 0);
                serpentCipher.DoFinal(serpentOutput, serpentLen);

                serpentEncrypted = new byte[ivSerpent.Length + serpentOutput.Length];
                Array.Copy(ivSerpent, 0, serpentEncrypted, 0, ivSerpent.Length);
                Array.Copy(serpentOutput, 0, serpentEncrypted, ivSerpent.Length, serpentOutput.Length);

                using (var aes = Aes.Create())
                {
                    aes.Key = _key;
                    aes.GenerateIV();

                    using (var memoryStream = new MemoryStream())
                    {
                        memoryStream.Write(aes.IV, 0, aes.IV.Length);

                        using (var cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(serpentEncrypted, 0, serpentEncrypted.Length);
                            cryptoStream.FlushFinalBlock();

                            return memoryStream.ToArray();
                        }
                    }
                }
            });
        }
    }
}
