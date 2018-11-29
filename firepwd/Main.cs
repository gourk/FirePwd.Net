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
using System.Collections.Generic;
using System.Security.Cryptography;

namespace firepwd
{
    class MainClass
    {
        static bool Verbose = false;
        public static int Main(string[] args)
        {
            string MasterPwd = string.Empty;

            byte[] privateKey = new byte[24];
            bool loginsFound = false, signonsFound = false;
            string signonsFile = string.Empty, loginsFile = string.Empty; ;
            string filePath = string.Empty;
            DBHelper dbh = new DBHelper();
            Converts conv = new Converts();
            // Read berkeleydb
            DataTable dt = new DataTable();
            Asn1Der asn = new Asn1Der();
            List<LoginFieldS> lp = new List<LoginFieldS>();

            List<string> dirs = Directory.GetDirectories(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Mozilla\\Firefox\\Profiles")).ToList();

            //Manage args
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].Equals("-p"))
                {
                    MasterPwd = args[i + 1];
                }

                if (args[i].Equals("-f"))
                {
                    dirs.Clear();
                    dirs.Add(args[i + 1]);
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
            foreach (string dir in dirs)
            {

                // Check if files exists
                string[] files = Directory.GetFiles(dir, "signons.sqlite");
                if (files.Length > 0)
                {
                    filePath = dir;
                    signonsFile = files[0];
                    signonsFound = true;
                }

                // find logins.json file
                files = Directory.GetFiles(dir, "logins.json");
                if (files.Length > 0)
                {
                    filePath = dir;
                    loginsFile = files[0];
                    loginsFound = true;
                }



                if (!loginsFound && !signonsFound)
                {
                    Console.WriteLine("File signons & logins not found.");
                    continue;

                }


                if (filePath == string.Empty)
                {

                    Console.WriteLine("Mozilla not found.");
                    continue;



                }

                if (Verbose)
                {
                    Console.WriteLine("Check if exist key3.db or key3.db");
                }

                // Check if files exists
                if (!File.Exists(Path.Combine(filePath, "key3.db")))
                    privateKey = dbh.CheckKey4DB(dir, MasterPwd, Verbose);
                else
                    privateKey = dbh.CheckKey3DB(dir, MasterPwd, Verbose);
                if (privateKey == null || privateKey.Length == 0)
                {
                    Console.WriteLine("Private key return null");
                    continue;

                }


                FFLogins ffLoginData;



                if (signonsFound)
                {

                    if (Verbose)
                    {
                        Console.WriteLine("Fetch users fron signons file");
                    }
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
                        string hostname = row["hostname"].ToString();
                        string decryptedUser = TripleDESHelper.DESCBCDecryptor(privateKey, user.objects[0].objects[1].objects[1].Data, user.objects[0].objects[2].Data);
                        string decryptedPwd = TripleDESHelper.DESCBCDecryptor(privateKey, pwd.objects[0].objects[1].objects[1].Data, pwd.objects[0].objects[2].Data);

                        string username = Regex.Replace(decryptedUser, @"[^\u0020-\u007F]", "");
                        string password = Regex.Replace(decryptedPwd, @"[^\u0020-\u007F]", "");

                        lp.Add(new LoginFieldS { url = hostname, userName = username, password = password });

                    }

                }
                if (loginsFound)
                {
                    if (Verbose)
                    {
                        Console.WriteLine("Fetch users fron logins file");
                    }
                    using (StreamReader sr = new StreamReader(Path.Combine(filePath, "logins.json")))
                    {
                        string json = sr.ReadToEnd();
                        ffLoginData = JsonConvert.DeserializeObject<FFLogins>(json);
                    }

                    foreach (LoginData loginData in ffLoginData.logins)
                    {

                        Asn1DerObject user = asn.Parse(Convert.FromBase64String(loginData.encryptedUsername));
                        Asn1DerObject pwd = asn.Parse(Convert.FromBase64String(loginData.encryptedPassword));
                        string hostname = loginData.hostname;
                        string decryptedUser = TripleDESHelper.DESCBCDecryptor(privateKey, user.objects[0].objects[1].objects[1].Data, user.objects[0].objects[2].Data);
                        string decryptedPwd = TripleDESHelper.DESCBCDecryptor(privateKey, pwd.objects[0].objects[1].objects[1].Data, pwd.objects[0].objects[2].Data);




                        string username = Regex.Replace(decryptedUser, @"[^\u0020-\u007F]", "");
                        string password = Regex.Replace(decryptedPwd, @"[^\u0020-\u007F]", "");

                        lp.Add(new LoginFieldS { url = hostname, userName = username, password = password });

                    }
                }

            }

            foreach (var userInfo in lp)

            {
                Console.WriteLine("===================================================");
               Console.WriteLine($"url:{userInfo.url}\nUsername: {userInfo.userName}\nPassword:{userInfo.password}");
                Console.WriteLine("===================================================");
            }


            Console.Read();
            return 0;
        }


    }
}
       
        

