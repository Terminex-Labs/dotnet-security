using System.Numerics;
using System.Security;
using Terminex.Security.Utilities;
using System.Security.Cryptography;
using Terminex.Security.Configuration.Srp;
using Terminex.Security.Abstraction.Models;
using Terminex.Security.Abstraction.Interfaces;

namespace Terminex.Security.Srp
{
    public class SrpClientService : ISrpClientService
    {
        public string GenerateVerifier(string authHash, SrpGroup group)
        {
            SrpOptions srpOptions = SrpOptionsRegistry.GetOptions(group);

            byte[] bytes = Convert.FromBase64String(authHash);

            BigInteger x = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);

            BigInteger verifier = BigInteger.ModPow(srpOptions.G, x, srpOptions.N);

            return Convert.ToBase64String(SrpUtilities.ToFixedLength(verifier, srpOptions));
        }

        public SrpProof GenerateProof(string identity, byte[] authHashBytes, string saltBase64, string bBase64, SrpGroup group)
        {
            SrpOptions srpOptions = SrpOptionsRegistry.GetOptions(group);

            byte[] saltBytes = StringUtilities.ToBytes(saltBase64);

            byte[]? aBytes = null;

            try
            {
                BigInteger x = new(authHashBytes, isUnsigned: true, isBigEndian: true);

                int privateKeySize = Math.Max(32, srpOptions.ModulesSize / 2);

                aBytes = new byte[privateKeySize];

                BigInteger a;

                do
                {
                    RandomNumberGenerator.Fill(aBytes);

                    a = new BigInteger(aBytes, isUnsigned: true, isBigEndian: true);
                }
                while (a == 0);

                BigInteger A = BigInteger.ModPow(srpOptions.G, a, srpOptions.N);

                if (A <= 0 || A >= srpOptions.N)
                    throw new SecurityException("Публичный клиентский ключ `A` не валиден!");

                byte[] bBytes = StringUtilities.ToBytes(bBase64);

                BigInteger B = new BigInteger(bBytes, isUnsigned: true, isBigEndian: true);

                if (B % srpOptions.N == 0 || B >= srpOptions.N)
                    throw new SecurityException("Публичный серверынй ключ `B` не валиден!");

                BigInteger u = SrpUtilities.HashModule(srpOptions, [A, B]);

                if (u == 0)
                    throw new SecurityException("Ошибка расчета параметра `u`!");

                BigInteger gX = BigInteger.ModPow(srpOptions.G, x, srpOptions.N);
                BigInteger term = srpOptions.ComputeK() * gX % srpOptions.N;
                BigInteger baseBigInt = (B - term + srpOptions.N) % srpOptions.N;
                BigInteger exponent = a + (u * x);
                BigInteger S = BigInteger.ModPow(baseBigInt, exponent, srpOptions.N);

                if (S == 0)
                    throw new SecurityException("Критическая ошибка!!!\nОбщий секрет `S` был равен нулю!");

                byte[] sessionKeyK = SrpUtilities.ComputeSessionKey(S, srpOptions);
                byte[] m1Bytes = SrpUtilities.ComputeM1(srpOptions, A, B, sessionKeyK, identity, saltBytes);

                string aBase64 = Convert.ToBase64String(SrpUtilities.ToFixedLength(A, srpOptions));
                string m1Base64 = Convert.ToBase64String(m1Bytes);

                SrpProof srpProof = new(aBase64, m1Base64, sessionKeyK);

                return srpProof;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(authHashBytes);
                CryptographicOperations.ZeroMemory(aBytes);
            }
        }

        public bool VerifyServerM2(string publicA, string m1, string serverM2, byte[] sessionKey, SrpGroup group)
        {
            SrpOptions srpOptions = SrpOptionsRegistry.GetOptions(group);

            BigInteger A = BigIntegerUtilities.FromBase64(publicA);

            byte[] m1Bytes = StringUtilities.ToBytes(m1);
            byte[] computedM2Bytes = SrpUtilities.ComputeM2(A, m1Bytes, sessionKey, srpOptions);

            byte[] serverM2Bytes = StringUtilities.ToBytes(serverM2);

            bool verified = CryptographicOperations.FixedTimeEquals(computedM2Bytes, serverM2Bytes);

            return verified;
        }
    }
}
