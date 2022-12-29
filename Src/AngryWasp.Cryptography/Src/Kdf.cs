using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace AngryWasp.Cryptography
{
    public static class Kdf
    {
        public static byte[] Hash128(byte[] message, byte[] salt, int iterations = 2048) => Hash(message, salt, iterations, 128);
        public static byte[] Hash224(byte[] message, byte[] salt, int iterations = 2048) => Hash(message, salt, iterations, 224);
        public static byte[] Hash256(byte[] message, byte[] salt, int iterations = 2048) => Hash(message, salt, iterations, 256);
        public static byte[] Hash288(byte[] message, byte[] salt, int iterations = 2048) => Hash(message, salt, iterations, 288);
        public static byte[] Hash384(byte[] message, byte[] salt, int iterations = 2048) => Hash(message, salt, iterations, 384);
        public static byte[] Hash512(byte[] message, byte[] salt, int iterations = 2048) => Hash(message, salt, iterations, 512);

        public static byte[] Hash(byte[] message, byte[] salt, int iterations, int keySize)
        {
            Pkcs5S2ParametersGenerator kdf = new Pkcs5S2ParametersGenerator();
            kdf.Init(message, salt, iterations);
            return ((KeyParameter)kdf.GenerateDerivedMacParameters(keySize)).GetKey();
        }
    }
}