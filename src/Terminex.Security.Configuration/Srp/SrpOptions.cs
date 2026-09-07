using System.Numerics;
using System.Security.Cryptography;

namespace Terminex.Security.Configuration.Srp
{
    public class SrpOptions
    {
        public SrpGroup Group { get; init; }
        public HashAlgorithmName AlgorithmName { get; init; }
        public int SizeSalt { get; init; }
        public BigInteger N => SrpGroupParameters.GetN(Group);
        public BigInteger G => SrpGroupParameters.GetG(Group);
        public int ModulesSize => (int)(N.GetBitLength() + 7) / 8;

        public BigInteger ComputeK()
        {
            using var hash = IncrementalHash.CreateHash(AlgorithmName);

            byte[] nBytes = N.ToByteArray(isUnsigned: true, isBigEndian: true);
            byte[] gBytes = G.ToByteArray(isUnsigned: true, isBigEndian: true);

            byte[] resultNButes = new byte[ModulesSize];
            byte[] resultGButes = new byte[ModulesSize];

            Buffer.BlockCopy(nBytes, 0, resultNButes, ModulesSize - nBytes.Length, nBytes.Length);
            Buffer.BlockCopy(gBytes, 0, resultGButes, ModulesSize - gBytes.Length, gBytes.Length);

            hash.AppendData(resultNButes);
            hash.AppendData(resultGButes);

            byte[] kBytes = hash.GetHashAndReset();

            return new BigInteger(kBytes, isUnsigned: true, isBigEndian: true);
        }
    }
}
