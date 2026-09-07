using Terminex.Security.Configuration.Crypto;

namespace Terminex.Security.Abstraction.Interfaces
{
    public interface IKeyDerivationService
    {
        (byte[] Kek, string AuthHash) FromPassword(string identifier, string password, byte[] salt, CryptoVersion version);
    }
}