namespace Terminex.Security.Abstraction.Models
{
    public record SrpProof(string A, string M1, byte[] SessionKeyK);
}
