using System;
using System.Text;
using System.Diagnostics;

namespace AngryWasp.Cryptography.Test
{
    internal class MainClass
    {
        private static void Main(string[] rawArgs)
        {
            var test = "Hello world, this is a random test string that we will attempt to encrypt and decrypt";
            int length = test.Length;
            var password = Encoding.ASCII.GetBytes("12345");
            var encrypted = Aes.Encrypt(Encoding.ASCII.GetBytes(test), password);
            var decrypt = Aes.Decrypt(encrypted, password, out byte[] decryptedBytes);
            var decrypted = Encoding.ASCII.GetString(decryptedBytes);
            Debug.Assert(decrypted == test, "Encryption test failed");
            
        }
    }
}