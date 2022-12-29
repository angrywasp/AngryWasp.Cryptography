using Org.BouncyCastle.Crypto.Digests;

namespace AngryWasp.Cryptography
{
    public static class Keccak
    {
        public static byte[] Hash128(byte[] input) => Hash(input, 128);
        public static byte[] Hash224(byte[] input) => Hash(input, 224);
        public static byte[] Hash256(byte[] input) => Hash(input, 256);
        public static byte[] Hash288(byte[] input) => Hash(input, 288);
        public static byte[] Hash384(byte[] input) => Hash(input, 384);
        public static byte[] Hash512(byte[] input) => Hash(input, 512);

        public static byte[] Hash(byte[] input, int digestSize)
        {
            var digest = new KeccakDigest(digestSize);
            var output = new byte[digest.GetDigestSize()];
            digest.BlockUpdate(input, 0, input.Length);
            digest.DoFinal(output, 0);
            return output;
        }
    }
}