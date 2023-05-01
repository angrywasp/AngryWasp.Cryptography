using System;
using Org.BouncyCastle.Math;

namespace AngryWasp.Cryptography
{
    public class ECDSASignature
    {
        public ECDSASignature(BigInteger r, BigInteger s)
        {
            R = r;
            S = s;
        }

        public ECDSASignature(byte[] r, byte[] s)
        {
            R = new BigInteger(1, r);
            S = new BigInteger(1, s);
        }

        public ECDSASignature(BigInteger[] rs)
        {
            R = rs[0];
            S = rs[1];
        }

        public BigInteger R { get; }

        public BigInteger S { get; }

        public byte[] V { get; set; }
    }
}