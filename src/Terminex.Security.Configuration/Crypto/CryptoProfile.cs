namespace Terminex.Security.Configuration.Crypto
{
    public class CryptoProfile
    {
        public CryptoVersion CryptoVersion { get; init; }
        public KdfOptions KdfOptions { get; init; } = null!;
        public AesGcmOptions AesGcmOptions { get; init; } = null!;
    }
}
