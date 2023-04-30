using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
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
    }
}
