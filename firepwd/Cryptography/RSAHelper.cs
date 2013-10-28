namespace NancyliconValley.Cryptography
{
    using System.Security.Cryptography;
    using System.Text;
    using System.Windows.Forms;

    //Testée NOK
    public class RSAHelper
    {

        #region Static public methods

        public static string RSAEncryptor(string value)
        {
            //Create a new instance of the RSACryptoServiceProvider class.
            RSAKeyManager manager = new RSAKeyManager();
            RSACryptoServiceProvider RSA = manager.GetKeyFromContainer();

            //Create a new instance of the RSAParameters structure.
            //RSAParameters RSAKeyInfo = new RSAParameters();

            //Set RSAKeyInfo to the public key values. 
            //RSAKeyInfo.Modulus = PublicKey;
            //RSAKeyInfo.Modulus = Encoding.Unicode.GetBytes(secretKey);

            //RSAKeyInfo.Exponent = Exponent;
            
            //Import key parameters into RSA.
            //RSA.ImportParameters(RSAKeyInfo);
            try
            {
                return RSA.Encrypt(Encoding.Unicode.GetBytes(value), false).ToString();
            }
            catch (CryptographicException ex)
            {
                MessageBox.Show(ex.Message);
                return string.Empty;
            }
            
        }

        public static string RSADecryptor(string value)
        {
            //Create a new instance of the RSACryptoServiceProvider class.
            RSAKeyManager manager = new RSAKeyManager();
            RSACryptoServiceProvider RSA = manager.GetKeyFromContainer();

            //Create a new instance of the RSAParameters structure.
            //RSAParameters RSAKeyInfo = new RSAParameters();

            //Set RSAKeyInfo to the public key values. 
            //RSAKeyInfo.Modulus = PublicKey;
            //RSAKeyInfo.Exponent = Exponent;

            //Import key parameters into RSA.
            //RSA.ImportParameters(RSAKeyInfo);

            return string.IsNullOrEmpty(value) ? string.Empty : RSA.Decrypt(Encoding.Unicode.GetBytes(value), false).ToString();
        }

        #endregion

    }
}
