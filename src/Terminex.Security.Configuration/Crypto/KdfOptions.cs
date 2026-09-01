using System.Security.Cryptography;

namespace Terminex.Security.Configuration.Crypto
{
    public sealed class KdfOptions
    {
        public int Pbkdf2Iteration { get; init; }
        public HashAlgorithmName HashAlgorithmName { get; init; }

        public static KdfOptions V1 => new() 
        { 
            Pbkdf2Iteration = 1_000_000,
            HashAlgorithmName = HashAlgorithmName.SHA256
        };
    }
}
