using System.Numerics;
using System.Security;
using Terminex.Security.Utilities;
using System.Security.Cryptography;
using Terminex.Security.Configuration.Srp;
using Terminex.Security.Abstraction.Models;
using Terminex.Security.Abstraction.Interfaces;

namespace Terminex.Security.Srp
{
    public class SrpServerService : ISrpServerService
    {
        public SrpSessionState GetChallenge(string identity, byte[] verifierBytes, byte[] salt, SrpGroup group)
        {
            if (string.IsNullOrWhiteSpace(identity))
                throw new ArgumentNullException(nameof(identity));

            if (verifierBytes == null)
                throw new ArgumentNullException(nameof(verifierBytes));

            if (salt == null)
                throw new ArgumentNullException(nameof(salt));

            SrpOptions options = SrpOptionsRegistry.GetOptions(group);

            BigInteger verifier = new(verifierBytes, isUnsigned: true, isBigEndian: true);

            if (verifier <= 0 || verifier >= options.N)
                throw new SecurityException("Произошла подмена данных!!!");

            int privateKeySize = Math.Max(32, options.ModulesSize / 2);

            byte[] bBytes;
            BigInteger B;

            while (true)
            {
                bBytes = new byte[privateKeySize];

                RandomNumberGenerator.Fill(bBytes);

                BigInteger b = new(bBytes, isUnsigned: true, isBigEndian: true);

                if (b == 0)
                    continue;

                BigInteger gB = BigInteger.ModPow(options.G, b, options.N);

                B = (options.ComputeK() * verifier + gB) % options.N;

                if (B != 0)
                    break;
            }

            if (B >= options.N)
                throw new SecurityException("Публичный ключ сервера не валиден!");

            SrpSessionState sessionState = new(identity, bBytes, SrpUtilities.ToFixedLength(B, options), verifierBytes, salt);

            return sessionState;
        }

        public string VerifyProof(SrpSessionState sessionState, string a, string m1, SrpGroup group)
        {
            SrpOptions options = SrpOptionsRegistry.GetOptions(group);

            BigInteger A = new(Convert.FromBase64String(a), isUnsigned: true, isBigEndian: true);
            BigInteger B = new(sessionState.PublicKeyB, isUnsigned: true, isBigEndian: true);
            BigInteger b = new(sessionState.PrivateKeyB, isUnsigned: true, isBigEndian: true);
            BigInteger v = new(sessionState.Verifier, isUnsigned: true, isBigEndian: true);

            if (v <= 0 || v >= options.N)
                throw new SecurityException("Верификатор не валиден!");

            if (A % options.N == 0)
                throw new SecurityException("Не корректное значение `A`!");

            if (A <= 0 || A >= options.N)
                throw new SecurityException("Не корректное значение `A`!\nВышел за пределы значения!");

            BigInteger u = SrpUtilities.HashModule(options, A, B);

            if (u == 0)
                throw new SecurityException("Ошибка в расчетах параметра `u`!");

            BigInteger vU = BigInteger.ModPow(v, u, options.N);
            BigInteger S = BigInteger.ModPow(A * vU % options.N, b, options.N);

            if (S == 0)
                throw new SecurityException("КРИТИЧЕСКАЯ ОШИБКА!!!\nОбщий секрет `SessionKey` равен нулю!");

            byte[] sessionKeyK = SrpUtilities.ComputeSessionKey(S, options);
            byte[] m1ServerBytes = SrpUtilities.ComputeM1(options, A, B, sessionKeyK, sessionState.Identity, sessionState.Salt);
            byte[] m1ClientBytes = Convert.FromBase64String(m1);

            if (!CryptographicOperations.FixedTimeEquals(m1ServerBytes, m1ClientBytes))
                throw new SecurityException("Не верные учетные данные!");

            byte[] m2ServerBytes = SrpUtilities.ComputeM2(A, m1ClientBytes, sessionKeyK, options);

            return Convert.ToBase64String(m2ServerBytes);
        }
    }
}
