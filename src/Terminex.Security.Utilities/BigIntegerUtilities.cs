using System.Numerics;
using System.Security.Cryptography;

namespace Terminex.Security.Utilities
{
    public static class BigIntegerUtilities
    {
        public static byte[] ToFixedLength(BigInteger value, int length)
        {
            if (length <= 0)
                throw new ArgumentException("Валидная длина должна быть больше нуля!");

            byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);

            if (bytes.Length == length)
                return bytes;

            if (bytes.Length > length)
                throw new ArgumentException($"Возможно данные были повреждены!\n" +
                                            $"Длина массива из значения `{value}` оказалось больше длины `{length}`!");

            byte[] result = new byte[length];

            Buffer.BlockCopy(bytes, 0, result, length - bytes.Length, bytes.Length);

            return result;
        }

        public static BigInteger FromBase64(string base64)
            => new (StringUtilities.ToBytes(base64), isUnsigned: true, isBigEndian: true);

        public static BigInteger HashBigInt(HashAlgorithmName algorithmName, params byte[][] values)
        {
            using var incrementalHash = IncrementalHash.CreateHash(algorithmName);

            foreach (var item in values)
                incrementalHash.AppendData(item);

            byte[] bytes = incrementalHash.GetHashAndReset();

            return new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        }

        public static byte[] HashByte(HashAlgorithmName algorithmName, params byte[][] values)
        {
            using var incrementalHash = IncrementalHash.CreateHash(algorithmName);

            foreach (var item in values)
                incrementalHash.AppendData(item);

            byte[] bytes = incrementalHash.GetHashAndReset();

            return bytes;
        }
    }
}
