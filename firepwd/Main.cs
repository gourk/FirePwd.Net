using System;
using System.Data;
using System.Data.SQLite;
using System.Linq;
using System.Text;
using firepwd.Cryptography;
using System.Text.RegularExpressions;
using System.IO;
using firepwd.net;
using Newtonsoft.Json;

namespace firepwd
{
    class MainClass
    {
        public static int Main(string[] args)
        {
            string MasterPwd = string.Empty;
            bool Verbose = false;
           
            string filePath = Directory.GetDirectories(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Mozilla\\Firefox\\Profiles"))[0];

            //Manage args
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].Equals("-p"))
                {
                    MasterPwd = args[i + 1];
                }

                if (args[i].Equals("-f"))
                {
                    filePath = args[i + 1];
                }

                if (args[i].Equals("-v"))
                {
                    Verbose = true;
                }

                if (args[i].Equals("-h"))
                {
                    Console.WriteLine("FirePwd.Net v0.1");
                    Console.WriteLine("Usage :");
                    Console.WriteLine("\t -p to specify Master Password");
                    Console.WriteLine("\t -v to activate verbose mode");
                    Console.WriteLine("\t -f to specify path for files key3.db and signons.sqlite");
                    return 0;
                }
            }

            // Check if files exists
            if (!File.Exists(Path.Combine(filePath,"key3.db")))
            {
                Console.WriteLine("File key3.db not found.");
                return 0;
            }

            if (!File.Exists(Path.Combine(filePath, "signons.sqlite")) && !File.Exists(Path.Combine(filePath, "logins.json")))
            {
                Console.WriteLine("File signons.sqlite/logins.json not found.");
                return 0;
            }

            // Read berkeleydb
            DataTable dt = new DataTable();
            Asn1Der asn = new Asn1Der();

            BerkeleyDB db = new BerkeleyDB(Path.Combine(filePath, "key3.db"));
            if (Verbose)
            {
                Console.WriteLine(db.Version);
            }

            // Verify MasterPassword
            PasswordCheck pwdCheck = new PasswordCheck((from p in db.Keys
                                                        where p.Key.Equals("password-check")
                                                        select p.Value).FirstOrDefault().Replace("-", ""));

            string GlobalSalt = (from p in db.Keys
                                 where p.Key.Equals("global-salt")
                                 select p.Value).FirstOrDefault().Replace("-", "");

            if (Verbose)
            {
                Console.WriteLine("GlobalSalt = " + GlobalSalt);
                Console.WriteLine("EntrySalt = " + pwdCheck.EntrySalt);
            }

            MozillaPBE CheckPwd = new MozillaPBE(ByteHelper.ConvertHexStringToByteArray(GlobalSalt), Encoding.ASCII.GetBytes(MasterPwd), ByteHelper.ConvertHexStringToByteArray(pwdCheck.EntrySalt));
            CheckPwd.Compute();
            string decryptedPwdChk = TripleDESHelper.DESCBCDecryptor(CheckPwd.Key, CheckPwd.IV, ByteHelper.ConvertHexStringToByteArray(pwdCheck.Passwordcheck));

            if (!decryptedPwdChk.StartsWith("password-check"))
            {
                Console.WriteLine("Master password is wrong !");
                return 0;
            }

            // Get private key
            string f81 = (from p in db.Keys
                          where !p.Key.Equals("global-salt")
                          && !p.Key.Equals("Version")
                          && !p.Key.Equals("password-check")
                          select p.Value).FirstOrDefault().Replace("-", "");

            Asn1DerObject f800001 = asn.Parse(ByteHelper.ConvertHexStringToByteArray(f81));

            if (Verbose)
            {
                Console.WriteLine("F800001");
                Console.WriteLine(f800001.ToString());
            }

            MozillaPBE CheckPrivateKey = new MozillaPBE(ByteHelper.ConvertHexStringToByteArray(GlobalSalt), Encoding.ASCII.GetBytes(MasterPwd), f800001.objects[0].objects[0].objects[1].objects[0].Data);
            CheckPrivateKey.Compute();

            byte[] decryptF800001 = TripleDESHelper.DESCBCDecryptorByte(CheckPrivateKey.Key, CheckPrivateKey.IV, f800001.objects[0].objects[1].Data);

            Asn1DerObject f800001deriv1 = asn.Parse(decryptF800001);

            if (Verbose)
            {
                Console.WriteLine("F800001 first derivation");
                Console.WriteLine(f800001deriv1.ToString());
            }


            Asn1DerObject f800001deriv2 = asn.Parse(f800001deriv1.objects[0].objects[2].Data);

            if (Verbose)
            {
                Console.WriteLine("F800001 second derivation");
                Console.WriteLine(f800001deriv2.ToString());
            }

            byte[] privateKey = new byte[24];

            if (f800001deriv2.objects[0].objects[3].Data.Length > 24)
            {
                Array.Copy(f800001deriv2.objects[0].objects[3].Data, f800001deriv2.objects[0].objects[3].Data.Length - 24, privateKey, 0, 24);
            }
            else
            {
                privateKey = f800001deriv2.objects[0].objects[3].Data;
            }

            if (Verbose)
            {
                Console.WriteLine("Private key = " + privateKey.ToString());
            }
            // decrypt username and password

            if (File.Exists(Path.Combine(filePath, "signons.sqlite")))
            {

                using (SQLiteConnection cnn = new SQLiteConnection("Data Source=" + Path.Combine(filePath, "signons.sqlite")))
                {
                    cnn.Open();
                    SQLiteCommand mycommand = new SQLiteCommand(cnn);
                    mycommand.CommandText = "select hostname, encryptedUsername, encryptedPassword, guid, encType from moz_logins;";
                    SQLiteDataReader reader = mycommand.ExecuteReader();
                    dt.Load(reader);
                }

                foreach (DataRow row in dt.Rows)
                {
                    Asn1DerObject user = asn.Parse(Convert.FromBase64String(row["encryptedUsername"].ToString()));
                    Asn1DerObject pwd = asn.Parse(Convert.FromBase64String(row["encryptedPassword"].ToString()));
                    if (Verbose)
                    {
                        Console.WriteLine("User= " + user.ToString());
                        Console.WriteLine("Pwd= " + pwd.ToString());
                    }

                    string hostname = row["hostname"].ToString();
                    string decryptedUser = TripleDESHelper.DESCBCDecryptor(privateKey, user.objects[0].objects[1].objects[1].Data, user.objects[0].objects[2].Data);
                    string decryptedPwd = TripleDESHelper.DESCBCDecryptor(privateKey, pwd.objects[0].objects[1].objects[1].Data, pwd.objects[0].objects[2].Data);

                    Console.WriteLine(hostname + " " + Regex.Replace(decryptedUser, @"[^\u0020-\u007F]", "") + " " + Regex.Replace(decryptedPwd, @"[^\u0020-\u007F]", ""));
                }
            }
            else if (File.Exists(Path.Combine(filePath, "logins.json")))
            {
                FFLogins ffLoginData;
                using (StreamReader sr = new StreamReader(Path.Combine(filePath, "logins.json")))
                {
                    string json = sr.ReadToEnd();
                    ffLoginData = JsonConvert.DeserializeObject<FFLogins>(json);
                }

                foreach (LoginData loginData in ffLoginData.logins)
                {
                    try
                    {
                        Asn1DerObject user = asn.Parse(Convert.FromBase64String(loginData.encryptedUsername));
                        Asn1DerObject pwd = asn.Parse(Convert.FromBase64String(loginData.encryptedPassword));
                        if (Verbose)
                        {
                            Console.WriteLine("User= " + user.ToString());
                            Console.WriteLine("Pwd= " + pwd.ToString());
                        }

                        string hostname = loginData.hostname;
                        string decryptedUser = TripleDESHelper.DESCBCDecryptor(privateKey, user.objects[0].objects[1].objects[1].Data, user.objects[0].objects[2].Data);
                        string decryptedPwd = TripleDESHelper.DESCBCDecryptor(privateKey, pwd.objects[0].objects[1].objects[1].Data, pwd.objects[0].objects[2].Data);

                        Console.WriteLine(hostname + " " + Regex.Replace(decryptedUser, @"[^\u0020-\u007F]", "") + " " + Regex.Replace(decryptedPwd, @"[^\u0020-\u007F]", ""));
               
                    }
                    catch (Exception e)
                    {
                        continue;
                    }
                }
            
            
            }
            Console.Read();
            return 0;
        }
    }
}
