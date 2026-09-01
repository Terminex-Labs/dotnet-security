using Terminex.Security.Configuration.Crypto;

namespace Terminex.Security.Abstraction.Interfaces
{
    public interface ICryptoService
    {
        TData? Decrypt<TData>(string encryptedDataBase64, byte[] key);
        string Encrypt<TData>(TData data, byte[] key, CryptoVersion version);
    }
}