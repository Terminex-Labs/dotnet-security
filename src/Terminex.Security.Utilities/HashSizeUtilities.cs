using System.Security.Cryptography;

namespace Terminex.Security.Utilities
{
    public static class HashSizeUtilities
    {
        public static int CalculateSize(HashAlgorithmName hashAlgorithm)
            => hashAlgorithm switch
            {
                var hash when hash == HashAlgorithmName.SHA256 => 32,
                var hash when hash == HashAlgorithmName.SHA384 => 48,
                var hash when hash == HashAlgorithmName.SHA512 => 64,
                _ => throw new ArgumentException("Данный алгоритм хэширования не поддерживается!")
            };
    }
}
