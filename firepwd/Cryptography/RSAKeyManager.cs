namespace NancyliconValley.Cryptography
{
    using System;
    using System.Security.Cryptography;

    public class RSAKeyManager
    {

        #region Private member variables
        private string containerName = string.Empty;
        #endregion

        #region Constructor
        public RSAKeyManager()
        {
            this.containerName = Environment.GetCommandLineArgs()[0];
        }
        public RSAKeyManager(string containerName)
        {
            this.containerName = containerName;
        }
        #endregion

        #region Private methods
        private RSACryptoServiceProvider GenKey_SaveInContainer()
        {
            // Create the CspParameters object and set the key container name used to store the RSA key pair.
            CspParameters cp = new CspParameters();
            cp.KeyContainerName = this.containerName;
            // Create a new instance of RSACryptoServiceProvider that accesses the key container MyKeyContainerName.
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(cp);
            rsa.KeySize = 512;
            rsa.PersistKeyInCsp = true;
            //cp.KeyPassword = "S€cure£$String*ùF4&_This@Application";
            return rsa;
        }
        #endregion

        #region Public methods
        public RSACryptoServiceProvider GetKeyFromContainer()
        {
            // Create the CspParameters object and set the key container name used to store the RSA key pair.
            CspParameters cp = new CspParameters();
            cp.KeyContainerName = this.containerName;
            // Create a new instance of RSACryptoServiceProvider that accesses the key container MyKeyContainerName.
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(cp);
            return rsa ?? this.GenKey_SaveInContainer();
        }

        public void DeleteKeyFromContainer()
        {
            // Create the CspParameters object and set the key container name used to store the RSA key pair.
            CspParameters cp = new CspParameters();
            cp.KeyContainerName = this.containerName;
            // Create a new instance of RSACryptoServiceProvider that accesses the key container.
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(cp);
            // Delete the key entry in the container.
            rsa.PersistKeyInCsp = false;
            // Call Clear to release resources and delete the key from the container.
            rsa.Clear();
        }
        #endregion

    }
}
