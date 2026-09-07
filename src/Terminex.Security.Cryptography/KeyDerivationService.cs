using System.Text;
using System.Security;
using Terminex.Security.Utilities;
using System.Security.Cryptography;
using Terminex.Security.Configuration.Crypto;
using Terminex.Security.Abstraction.Interfaces;

namespace Terminex.Security.Cryptography
{
    public class KeyDerivationService : IKeyDerivationService
    {
        public (byte[] Kek, string AuthHash) FromPassword(string identity, string password, byte[] salt, CryptoVersion version)
        {
            if (string.IsNullOrWhiteSpace(identity))
                throw new ArgumentException("Идентификатор был пуст!");

            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Пароль был пуст!");

            if (salt == null)
                throw new ArgumentException("Соль была пуста!");

            if (salt.Length < 16)
                throw new ArgumentException("Соль была меньше 16!");

            CryptoProfile cryptoProfile = CryptoProfileRegistry.GetCryptoProfile(version);

            KdfOptions kdfOptions = cryptoProfile.KdfOptions;

            string combination = $"{identity}:{password}";

            byte[]? masterKey = null;

            try
            {
                int hashSize = HashSizeUtilities.CalculateSize(kdfOptions.HashAlgorithmName);

                masterKey = Rfc2898DeriveBytes.Pbkdf2(combination, salt, kdfOptions.Pbkdf2Iteration, kdfOptions.HashAlgorithmName, hashSize);

                byte[] emptySalt = [];

                byte[] kek = HKDF.DeriveKey(kdfOptions.HashAlgorithmName, masterKey, 32, emptySalt, Encoding.UTF8.GetBytes("AES-GCM-KEK-v1"));
                byte[] authHahs = HKDF.DeriveKey(kdfOptions.HashAlgorithmName, masterKey, 32, emptySalt, Encoding.UTF8.GetBytes("SERVER-AUTH-HASH-v1"));

                string authHashString = Convert.ToBase64String(authHahs);

                // Криптографически правильный метод очистки массива байт
                CryptographicOperations.ZeroMemory(authHahs);

                return (kek, authHashString);
            }
            catch (Exception ex) when (!(ex is ArgumentException || ex is SecurityException))
            {
                throw new SecurityException("Не удалось вывести ключи!", ex);
            }
            finally
            {
                if (masterKey != null)
                    CryptographicOperations.ZeroMemory(masterKey);
            }
        }
    }
}
