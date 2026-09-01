using System.Security.Cryptography;

namespace Terminex.Security.Abstraction.Models
{
    public class SrpSessionState : IDisposable
    {
        public string Identity { get; init; } = null!;
        public byte[] PrivateKeyB { get; init; } = null!;
        public byte[] PublicKeyB { get; init; } = null!;
        public byte[] Verifier { get; init; } = null!;
        public byte[] Salt { get; init; } = null!;

        public SrpSessionState(string identity, byte[] privateKeyB, byte[] publicKeyB, byte[] verifier, byte[] salt)
        {
            Identity = identity;
            PrivateKeyB = privateKeyB;
            PublicKeyB = publicKeyB;
            Verifier = verifier;
            Salt = salt;
        }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(Verifier);
            CryptographicOperations.ZeroMemory(PrivateKeyB);
        }
    }
}
