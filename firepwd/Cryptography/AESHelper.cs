namespace NancyliconValley.Cryptography
{
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    using NancyliconValley.Logging;

    // Testée OK
    public class AESHelper
    {
        #region Private constantes and private static member variables
        private const string secretKey = "N@ncyl€|";
        private static Log log = new Log("NancyliconValley.Crytpography");
        #endregion

        #region Public static methods
        public static byte[] AESEncryptor(string value)
        {
            return AESEncryptorMain(Encoding.Unicode.GetBytes(value));
        }

        public static string AESDecryptor(byte[] value)
        {
            return Encoding.Unicode.GetString(AESDecryptorMain(value));
        }
        #endregion

        #region Private static methods
        private static byte[] AESDecryptorMain(byte[] value)
        {
            try
            {
                // Setup decrytion algorithm
                byte[] salt = new byte[8];
                for (int i = 0; i < salt.Length; i++)
                {
                    salt[i] = value[i];
                }
                Rfc2898DeriveBytes keyGenerator = new Rfc2898DeriveBytes(secretKey, salt);
                Rijndael aes = Rijndael.Create();
                aes.IV = keyGenerator.GetBytes(aes.BlockSize / 8);
                aes.Key = keyGenerator.GetBytes(aes.KeySize / 8);

                // Decrypt data
                using (MemoryStream memoryStream = new MemoryStream())
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(value, 8, value.Length - 8);
                    cryptoStream.Close();
                    byte[] decrypted = memoryStream.ToArray();
                    return decrypted;
                }
            }
            catch (CryptographicException ex)
            {
                log.Write("AESDecryptorMain", ex.ToString(), System.Diagnostics.TraceEventType.Error);
                byte[] salt = new byte[1];
                for (int i = 0; i < salt.Length; i++)
                {
                    salt[i] = 0;
                }
                return salt;
            }
        }

        private static byte[] AESEncryptorMain(byte[] value)
        {
            try
            {
                // Setup encryption algorithm
                Rfc2898DeriveBytes keyGenerator = new Rfc2898DeriveBytes(secretKey, 8);
                Rijndael aes = Rijndael.Create();
                aes.IV = keyGenerator.GetBytes(aes.BlockSize / 8);
                aes.Key = keyGenerator.GetBytes(aes.KeySize / 8);
                
                // Encrypt data
                using (MemoryStream memoryStream = new MemoryStream())
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    memoryStream.Write(keyGenerator.Salt, 0, keyGenerator.Salt.Length);
                    cryptoStream.Write(value, 0, value.Length);
                    cryptoStream.Close();
                    byte[] encrypted = memoryStream.ToArray();
                    return encrypted;
                }
            }
            catch (CryptographicException ex)
            {
                log.Write("AESEncryptorMain", ex.ToString(), System.Diagnostics.TraceEventType.Error);
                byte[] salt = new byte[1];
                for (int i = 0; i < salt.Length; i++)
                {
                    salt[i] = 0;
                }
                return salt;
            }
        }
        #endregion

    }
}
