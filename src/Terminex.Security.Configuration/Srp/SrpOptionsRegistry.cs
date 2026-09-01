using System.Security.Cryptography;

namespace Terminex.Security.Configuration.Srp
{
    public static class SrpOptionsRegistry
    {
        public static SrpOptions GetOptions(SrpGroup group)
        {
            var hashAlgorithm = group switch
            {
                SrpGroup.Group2048 or SrpGroup.Group3072 => HashAlgorithmName.SHA256,
                SrpGroup.Group4096 or SrpGroup.Group6144 or SrpGroup.Group8192 => HashAlgorithmName.SHA384,
                _ => throw new NotSupportedException("Данная группа SRP не поддерживается!")
            };

            return new SrpOptions
            {
                Group = group,
                AlgorithmName = hashAlgorithm,
                SizeSalt = 32
            };
        }
    }
}
