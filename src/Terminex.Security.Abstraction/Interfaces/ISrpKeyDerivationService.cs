using Terminex.Security.Configuration.Crypto;

namespace Terminex.Security.Abstraction.Interfaces
{
    public interface ISrpKeyDerivationService
    {
        byte[] FromPassword(string identifier, string password, byte[] salt, CryptoVersion version);
    }
}