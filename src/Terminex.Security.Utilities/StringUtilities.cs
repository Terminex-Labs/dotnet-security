namespace Terminex.Security.Utilities
{
    public static class StringUtilities
    {
        public static byte[] ToBytes(string base64)
        {
            if (string.IsNullOrWhiteSpace(base64))
                throw new ArgumentNullException(nameof(base64));

            string cleaned = base64.Replace('-', '+').Replace('_', '/');

            int mod = cleaned.Length % 4;

            if (mod != 0)
                cleaned += new string('=', 4 - mod);

            return Convert.FromBase64String(cleaned);
        }
    }
}
