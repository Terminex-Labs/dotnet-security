using System.Text;
using System.Security;
using System.Text.Json;
using System.Security.Cryptography;
using Terminex.Security.Configuration.Crypto;
using Terminex.Security.Abstraction.Interfaces;

namespace Terminex.Security.Cryptography
{
    public class CryptoService : ICryptoService
    {
        public string Encrypt<TData>(TData data, byte[] key, CryptoVersion version)
        {
            if (data == null)
                throw new ArgumentException("Переданные данные для шифрования были пусты!");

            if (key == null)
                throw new ArgumentException("Ключ был пуст!");

            if (key.Length != 32)
                throw new ArgumentException("Ключ не соответствовал длине 32!");

            CryptoProfile cryptoProfile = CryptoProfileRegistry.GetCryptoProfile(version);

            AesGcmOptions aesGcmOptions = cryptoProfile.AesGcmOptions;

            byte[] plainBytes;

            if (data is byte[] bytes)
            {
                string base64String = Convert.ToBase64String(bytes);
                plainBytes = Encoding.UTF8.GetBytes($"\"{base64String}\"");
            }
            else
                plainBytes = JsonSerializer.SerializeToUtf8Bytes(data);

            byte[] nonce = new byte[aesGcmOptions.NonceSize];

            RandomNumberGenerator.Fill(nonce);

            byte[] cipherText = new byte[plainBytes.Length];
            byte[] tag = new byte[aesGcmOptions.TagSize];

            try
            {
                using var aes = new AesGcm(key, aesGcmOptions.TagSize);

                aes.Encrypt(nonce, plainBytes, cipherText, tag);
            }
            catch (CryptographicException ex)
            {
                throw new SecurityException("Ошибка шифрования!", ex);
            }
            finally
            {
                Array.Clear(plainBytes, 0, plainBytes.Length);
            }

            byte[] result = new byte[1 + aesGcmOptions.NonceSize + cipherText.Length + aesGcmOptions.TagSize];

            result[0] = (byte)version;

            Span<byte> resultSpan = result.AsSpan(1);

            nonce.CopyTo(resultSpan.Slice(0, aesGcmOptions.NonceSize));
            cipherText.CopyTo(resultSpan.Slice(aesGcmOptions.NonceSize, cipherText.Length));
            tag.CopyTo(resultSpan.Slice(aesGcmOptions.NonceSize + cipherText.Length, aesGcmOptions.TagSize));

            return Convert.ToBase64String(result);
        }

        public TData? Decrypt<TData>(string encryptedDataBase64, byte[] key)
        {
            if (string.IsNullOrWhiteSpace(encryptedDataBase64))
                throw new ArgumentException("Данные не были переданы!");

            if (key == null)
                throw new ArgumentException("Ключ был пуст!");

            if (key.Length != 32)
                throw new ArgumentException("Ключ не соответствовал длине 32!");

            byte[] encryptedBytes;

            try
            {
                encryptedBytes = Convert.FromBase64String(encryptedDataBase64);
            }
            catch (FormatException ex)
            {
                throw new ArgumentException("Не правильынй Base64 формат!", ex);
            }

            CryptoVersion version = (CryptoVersion)encryptedBytes[0];

            CryptoProfile cryptoProfile = CryptoProfileRegistry.GetCryptoProfile(version);

            AesGcmOptions aesGcmOptions = cryptoProfile.AesGcmOptions;

            Span<byte> resultSpan = encryptedBytes.AsSpan(1);

            if (resultSpan.Length < aesGcmOptions.NonceSize + aesGcmOptions.TagSize)
                throw new SecurityException($"Зишифрованные данные слишком короткие! Оно не соотвествует размеру {aesGcmOptions.NonceSize + aesGcmOptions.TagSize} байтов, но получил {encryptedBytes.Length}");

            Span<byte> nonce = resultSpan.Slice(0, aesGcmOptions.NonceSize);
            Span<byte> tag = resultSpan.Slice(resultSpan.Length - aesGcmOptions.TagSize, aesGcmOptions.TagSize);
            Span<byte> cipherText = resultSpan.Slice(aesGcmOptions.NonceSize, resultSpan.Length - aesGcmOptions.NonceSize - aesGcmOptions.TagSize);

            byte[] plainBytes = new byte[cipherText.Length];

            try
            {
                using var aes = new AesGcm(key, aesGcmOptions.TagSize);

                aes.Decrypt(nonce, cipherText, tag, plainBytes);

                if (typeof(TData) == typeof(byte[]))
                {
                    string jsonString = Encoding.UTF8.GetString(plainBytes);
                    string? base64String = JsonSerializer.Deserialize<string>(jsonString);

                    if (string.IsNullOrWhiteSpace(base64String))
                        return default;

                    byte[] result = Convert.FromBase64String(base64String);

                    return (TData?)(object?)result;
                }

                return JsonSerializer.Deserialize<TData>(plainBytes);
            }
            catch (CryptographicException ex)
            {
                throw new SecurityException("Ошибка расшифровки данных!\nДанные были повреждены!", ex);
            }
            finally
            {
                Array.Clear(plainBytes, 0, plainBytes.Length);
            }
        }
    }
}
