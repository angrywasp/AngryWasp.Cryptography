using System;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace AngryWasp.Cryptography
{
    public class ECKey
    {
        internal static readonly X9ECParameters secp256k1 = SecNamedCurves.GetByName("secp256k1");
        private static readonly BigInteger prime = new BigInteger(1, Org.BouncyCastle.Utilities.Encoders.Hex.Decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"));

        private readonly ECPrivateKeyParameters ecPrivateKeyParameters;
        private readonly ECPublicKeyParameters ecPublicKeyParameters;

        public ECPrivateKeyParameters PrivateKeyParameters => ecPrivateKeyParameters;
        public ECPublicKeyParameters PublicKeyParameters => ecPublicKeyParameters;

        public static ECKey FromPrivateKey(byte[] privateKey) => new ECKey(privateKey, true);
        public static ECKey FromPublicKey(byte[] publicKey) => new ECKey(publicKey, false);

        internal ECKey(byte[] key, bool isPrivate)
        {
            var domainParameter = new ECDomainParameters(secp256k1.Curve, secp256k1.G, secp256k1.N, secp256k1.H);

            if (isPrivate)
            {
                ecPrivateKeyParameters = new ECPrivateKeyParameters(new BigInteger(1, key), domainParameter);
                ecPublicKeyParameters = new ECPublicKeyParameters("EC", secp256k1.G.Multiply(PrivateKeyParameters.D), domainParameter);
            }
            else
            {
                ecPrivateKeyParameters = null;
                ecPublicKeyParameters = new ECPublicKeyParameters("EC", secp256k1.Curve.DecodePoint(key), domainParameter);
            }
        }

        public byte[] GetPubKey(bool isCompressed)
        {
            var q = ecPublicKeyParameters.Q.Normalize();
            return secp256k1.Curve.CreatePoint(q.XCoord.ToBigInteger(), q.YCoord.ToBigInteger()).GetEncoded(isCompressed);
        }

        public static ECKey RecoverFromSignature(int recId, ECDSASignature sig, byte[] message, bool compressed)
        {
            if (recId < 0)
                throw new ArgumentException("recId should be positive");
            if (sig.R.SignValue < 0)
                throw new ArgumentException("r should be positive");
            if (sig.S.SignValue < 0)
                throw new ArgumentException("s should be positive");
            if (message == null)
                throw new ArgumentNullException("message");

            var curve = secp256k1;

            var n = curve.N;
            var i = BigInteger.ValueOf((long)recId / 2);
            var x = sig.R.Add(i.Multiply(n));

            if (x.CompareTo(prime) >= 0)
            {
                Console.WriteLine("x.CompareTo(PRIME) >= 0");
                return null;
            }

            var compEnc = X9IntegerConverter.IntegerToBytes(x, 1 + X9IntegerConverter.GetByteLength(secp256k1.Curve));
            compEnc[0] = (byte)((recId & 1) == 1 ? 0x03 : 0x02);
            var R = secp256k1.Curve.DecodePoint(compEnc);

            if (!R.Multiply(n).IsInfinity)
            {
                Console.WriteLine("!R.Multiply(n).IsInfinity");
                return null;
            }

            var e = new BigInteger(1, message);
            var eInv = BigInteger.Zero.Subtract(e).Mod(n);
            var rInv = sig.R.ModInverse(n);
            var srInv = rInv.Multiply(sig.S).Mod(n);
            var eInvrInv = rInv.Multiply(eInv).Mod(n);
            var q = ECAlgorithms.SumOfTwoMultiplies(curve.G, eInvrInv, R, srInv);
            q = q.Normalize();
            if (compressed)
            {
                q = secp256k1.Curve.CreatePoint(q.XCoord.ToBigInteger(), q.YCoord.ToBigInteger());
                return ECKey.FromPublicKey(q.GetEncoded(true));
            }
            return ECKey.FromPublicKey(q.GetEncoded());
        }

        public virtual ECDSASignature Sign(byte[] hash)
        {
            if (PrivateKeyParameters == null)
                throw new InvalidOperationException("This key should be a private key for such operation");

            var signer = new ECDsaSigner();
            signer.Init(true, PrivateKeyParameters);
            return new ECDSASignature(signer.GenerateSignature(hash));
        }

        public bool Verify(byte[] hash, ECDSASignature sig)
        {
            var signer = new ECDsaSigner();
            signer.Init(false, ecPublicKeyParameters);
            return signer.VerifySignature(hash, sig.R, sig.S);
        }
    }
}