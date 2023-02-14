using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace AngryWasp.Cryptography
{
    public static class Aes
    {
        private const int keySize = 128;

        public static byte[] Encrypt(byte[] input, byte[] key, int kdfIterations = 2048)
        {
            var saltStringBytes = Helper.GenerateSecureBytes(keySize / 8);
            var ivStringBytes = Helper.GenerateSecureBytes(keySize / 8);

            var keyBytes = Kdf.Hash128(key, saltStringBytes, kdfIterations);

            using (var symmetricKey = System.Security.Cryptography.Aes.Create())
            {
                symmetricKey.BlockSize = keySize;
                symmetricKey.Mode = CipherMode.CBC;
                symmetricKey.Padding = PaddingMode.PKCS7;

                using (var encryptor = symmetricKey.CreateEncryptor(keyBytes, ivStringBytes))
                {
                    using (var memoryStream = new MemoryStream())
                    {
                        using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(input, 0, input.Length);
                            cryptoStream.FlushFinalBlock();
                            return saltStringBytes.Concat(ivStringBytes).Concat(memoryStream.ToArray()).ToArray();
                        }
                    }
                }
            }
        }

        public static bool Decrypt(byte[] input, byte[] key, out byte[] decrypted, int kdfIterations = 2048)
        {
            try
            {
                var saltStringBytes = input.Take(keySize / 8).ToArray();
                var ivStringBytes = input.Skip(keySize / 8).Take(keySize / 8).ToArray();
                var cipherTextBytes = input.Skip((keySize / 8) * 2).ToArray();

                var keyBytes = Kdf.Hash128(key, saltStringBytes, kdfIterations);

                using (var symmetricKey = System.Security.Cryptography.Aes.Create())
                {
                    symmetricKey.BlockSize = keySize;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;

                    using (var decryptor = symmetricKey.CreateDecryptor(keyBytes, ivStringBytes))
                    {
                        using (var cryptoStream = new CryptoStream(new MemoryStream(cipherTextBytes), decryptor, CryptoStreamMode.Read))
                        {
                            var ms = new MemoryStream();
                            cryptoStream.CopyTo(ms);
                            decrypted = ms.ToArray();
                            return true;
                        }
                    }
                }
            }
            catch
            {
                decrypted = null;
                return false;
            }
        }
    }
}