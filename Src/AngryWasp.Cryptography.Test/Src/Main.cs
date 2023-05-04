using AngryWasp.Helpers;
using System.Text;
using AngryWasp.Cryptography;
using Xunit;

public class MainClass
{
    const string TEST_STRING = "Hello world, this is a random test string that we will attempt to encrypt and decrypt";

    [Fact]
    public void KeyTest()
    {
        var (pubKey, privKey) = Ecc.GenerateKeyPair();
        Assert.True(pubKey.SequenceEqual(Ecc.GetPublicKeyFromPrivateKey(privKey)));
    }

    [Fact]
    public void AesTest()
    {
        var password = Encoding.ASCII.GetBytes("12345");
        var encrypted = Aes.Encrypt(Encoding.ASCII.GetBytes(TEST_STRING), password);
        var decrypt = Aes.Decrypt(encrypted, password, out byte[] decryptedBytes);
        var decrypted = Encoding.ASCII.GetString(decryptedBytes);
        Assert.True(decrypted == TEST_STRING);
    }

    [Fact]
    public void Base58Test()
    {
        var (pubKey, priKey) = Ecc.GenerateKeyPair();
        var ecKey = ECKey.FromPrivateKey(priKey);
        Assert.True(ecKey.GetPubKey(false).SequenceEqual(pubKey));
        var b58Address = Base58.EncodeWithCheckSum(ecKey.GetPubKey(true));
        Console.WriteLine(b58Address);
        Assert.True(Base58.DecodeWithCheckSum(b58Address, out _));
    }

    [Fact]
    public void SigningTest()
    {
        var (pubKey, priKey) = Ecc.GenerateKeyPair();
        var ecKey = ECKey.FromPrivateKey(priKey);
        Assert.True(ecKey.GetPubKey(false).SequenceEqual(pubKey));

        var hash = Keccak.Hash256(Encoding.ASCII.GetBytes(TEST_STRING));
        var sig = ecKey.Sign(hash);
        Assert.True(ecKey.Verify(hash, sig));
    }
}
