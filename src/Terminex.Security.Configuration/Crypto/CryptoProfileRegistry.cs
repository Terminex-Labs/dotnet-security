using System.Security;

namespace Terminex.Security.Configuration.Crypto
{
    public static class CryptoProfileRegistry
    {
        public static CryptoProfile GetCryptoProfile(CryptoVersion version)
        {
            return version switch
            {
                CryptoVersion.V1 => new CryptoProfile
                {
                    CryptoVersion = CryptoVersion.V1,
                    KdfOptions = KdfOptions.V1,
                    AesGcmOptions = AesGcmOptions.V1,
                },
                _ => throw new SecurityException("Данная версия не поддерживается!")
            };
        }
    }
}
