using Terminex.Security.Configuration.Srp;
using Terminex.Security.Abstraction.Models;

namespace Terminex.Security.Abstraction.Interfaces
{
    public interface ISrpServerService
    {
        SrpSessionState GetChallenge(string identity, byte[] verifierBytes, byte[] salt, SrpGroup group);
        string VerifyProof(SrpSessionState sessionState, string a, string m1, SrpGroup group);
    }
}