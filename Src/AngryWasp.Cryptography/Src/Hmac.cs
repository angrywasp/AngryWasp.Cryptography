using System;
using System.Security.Cryptography;

namespace AngryWasp.Cryptography
{
    public static class Hmac
    {
        public static byte[] Hash256(byte[] key, byte[] data) => new HMACSHA256(key).ComputeHash(data);

        public static byte[] Hash512(byte[] key, byte[] data) => new HMACSHA512(key).ComputeHash(data);

        public static bool Hash512(byte[] key, ReadOnlySpan<byte> data, Span<byte> output, out int outputLength)
		{
			using var hmac = new HMACSHA512(key);
			return hmac.TryComputeHash(data, output, out outputLength);
		}
    }
}