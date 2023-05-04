using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace AngryWasp.Cryptography
{
    public static class Ecc
    {
        private const string ALGORITHM = "secp256k1";
        private const string SIGNING_ALGORITHM = "SHA-256withECDSA";

        public static (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair()
        {
            var secp256k1 = SecNamedCurves.GetByName(ALGORITHM);
            var domain = new ECDomainParameters(secp256k1.Curve, secp256k1.G, secp256k1.N, secp256k1.H);
            ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
            keyPairGenerator.Init(new ECKeyGenerationParameters(domain, new SecureRandom()));
            var pair = keyPairGenerator.GenerateKeyPair();

            var publicKey = ((ECPublicKeyParameters)pair.Public).Q.GetEncoded();
            var privateKey = ((ECPrivateKeyParameters)pair.Private).D.ToByteArray();

            return (publicKey, privateKey);
        }

        public static byte[] GetPublicKeyFromPrivateKey(byte[] privateKey = null)
        {
            if (privateKey == null)
                privateKey = Helper.GenerateSecureBytes(65);

            var curve = SecNamedCurves.GetByName(ALGORITHM);
            var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
            var d = new BigInteger(privateKey);
            var q = domain.G.Multiply(d);
            var publicKey = new ECPublicKeyParameters(q, domain);
            return publicKey.Q.GetEncoded();
        }

         public static byte[] Sign(byte[] input, byte[] privateKey)
        {
            var curve = SecNamedCurves.GetByName(ALGORITHM);
            var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
            var keyParameters = new ECPrivateKeyParameters(new BigInteger(privateKey), domain);

            var signer = SignerUtilities.GetSigner(SIGNING_ALGORITHM);
            signer.Init(true, keyParameters);
            signer.BlockUpdate(input, 0, input.Length);
            return signer.GenerateSignature();
        }

        public static bool Verify(byte[] input, byte[] publicKey, byte[] signature)
        {
            try
            {
                var curve = SecNamedCurves.GetByName(ALGORITHM);
                var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
                var q = curve.Curve.DecodePoint(publicKey);
                var keyParameters = new ECPublicKeyParameters(q, domain);

                var signer = SignerUtilities.GetSigner(SIGNING_ALGORITHM);
                signer.Init(false, keyParameters);
                signer.BlockUpdate(input, 0, input.Length);
                return signer.VerifySignature(signature);
            }
            catch { return false; }
        }

        public static byte[] CreateKeyAgreement(byte[] senderPrivateKey, byte[] recipientPublicKey)
        {
            try
            {
                var curve = SecNamedCurves.GetByName(ALGORITHM);
                var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
                var priKp = new ECPrivateKeyParameters(new BigInteger(senderPrivateKey), domain);

                var q = curve.Curve.DecodePoint(recipientPublicKey);
                var pubKp = new ECPublicKeyParameters(q, domain);

                IBasicAgreement a = AgreementUtilities.GetBasicAgreement("ECDH");
                a.Init(priKp);
                BigInteger shared = a.CalculateAgreement(pubKp);

                return shared.ToByteArray();
            }
            catch { return null; }
        }
    }
}
