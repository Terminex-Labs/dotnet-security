using System.Security.Cryptography;

namespace Terminex.Security.Utilities
{
    public static class RandomUtilities
    {
        public static byte[] GenerateRandomBytes(int length = 32)
        {
            byte[] bytes = new byte[length];

            RandomNumberGenerator.Fill(bytes);

            return bytes;
        }
    }
}
