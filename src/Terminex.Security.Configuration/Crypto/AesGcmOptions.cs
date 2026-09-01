namespace Terminex.Security.Configuration.Crypto
{
    public class AesGcmOptions
    {
        public int NonceSize { get; init; }
        public int TagSize { get; init; }

        public static AesGcmOptions V1 => new()
        {
            NonceSize = 12,
            TagSize = 16,
        };
    }
}
