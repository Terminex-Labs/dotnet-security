using Terminex.Security.Configuration.Srp;
using Terminex.Security.Abstraction.Models;

namespace Terminex.Security.Abstraction.Interfaces
{
    public interface ISrpClientService
    {
        SrpProof GenerateProof(string identity, byte[] authHashBytes, string saltBase64, string bBase64, SrpGroup group);
        string GenerateVerifier(string authHash, SrpGroup group);
        bool VerifyServerM2(string publicA, string m1, string serverM2, byte[] sessionKey, SrpGroup group);
    }
}