using Org.BouncyCastle.Crypto.Digests;

namespace AngryWasp.Cryptography
{
    public static class Sha
    {
        public static byte[] Hash256(byte[] input)
        {
            var digest = new Sha256Digest();
            var output = new byte[digest.GetDigestSize()];
            digest.BlockUpdate(input, 0, input.Length);
            digest.DoFinal(output, 0);
            return output;
        }

        public static byte[] Hash512(byte[] input)
        {
            var digest = new Sha512Digest();
            var output = new byte[digest.GetDigestSize()];
            digest.BlockUpdate(input, 0, input.Length);
            digest.DoFinal(output, 0);
            return output;
        }
    }
}