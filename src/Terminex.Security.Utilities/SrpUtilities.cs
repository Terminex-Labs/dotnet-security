using System.Numerics;
using System.Text;
using Terminex.Security.Configuration.Srp;

namespace Terminex.Security.Utilities
{
    public static class SrpUtilities
    {
        public static byte[] ToFixedLength(BigInteger value, SrpOptions options) 
            => BigIntegerUtilities.ToFixedLength(value, options.ModulesSize);

        public static BigInteger HashModule(SrpOptions options, params BigInteger[] values)
            => BigIntegerUtilities.HashBigInt(options.AlgorithmName, [.. values.Select(x => ToFixedLength(x, options))]);

        public static byte[] ComputeSessionKey(BigInteger S, SrpOptions options)
            => BigIntegerUtilities.HashByte(options.AlgorithmName, S.ToByteArray(isUnsigned: true, isBigEndian: true));

        public static byte[] ComputeM1(SrpOptions options, BigInteger A, BigInteger B, byte[] sessionKeyK, string identity, byte[] saltBytes)
        {
            byte[] nBytes = ToFixedLength(options.N, options);
            byte[] gBytes = ToFixedLength(options.G, options);

            byte[] aBytes = ToFixedLength(A, options);
            byte[] bBytes = ToFixedLength(B, options);

            byte[] hashN = BigIntegerUtilities.HashByte(options.AlgorithmName, nBytes);
            byte[] hashG = BigIntegerUtilities.HashByte(options.AlgorithmName, gBytes);

            byte[] xorng = new byte[hashN.Length];

            for (int i = 0; i < hashN.Length; i++)
                xorng[i] = (byte)(hashN[i] ^ hashG[i]);

            byte[] hashIdentity = BigIntegerUtilities.HashByte(options.AlgorithmName, Encoding.UTF8.GetBytes(identity));
            byte[] m1Byte = BigIntegerUtilities.HashByte(options.AlgorithmName, xorng, hashIdentity, saltBytes, aBytes, bBytes, sessionKeyK);

            return m1Byte;
        }

        public static byte[] ComputeM2(BigInteger A, byte[] m1Bytes, byte[] sessionKey, SrpOptions options)
            => BigIntegerUtilities.HashByte(options.AlgorithmName, ToFixedLength(A, options), m1Bytes, sessionKey);
    }
}
