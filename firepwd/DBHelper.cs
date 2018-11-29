using firepwd.Cryptography;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace firepwd.net
{
    class DBHelper
    {   
      public  byte[] CheckKey4DB(string dir, string masterPwd,bool Verbose)
        {
            try
            {

                Asn1Der asn = new Asn1Der();
                byte[] item2 = new byte[] { };
                byte[] item1 = new byte[] { };
                byte[] a11 = new byte[] { };
                byte[] a102 = new byte[] { };
                string query = "SELECT item1,item2 FROM metadata WHERE id = 'password'";
                if (Verbose)
                {
                    Console.WriteLine("Fetch data from key4.db file");
                }
                GetItemsFromQuery(dir, ref item1, ref item2, query);
                Asn1DerObject f800001 = asn.Parse(item2);
                MozillaPBE CheckPwd = new MozillaPBE(item1, Encoding.ASCII.GetBytes(""), f800001.objects[0].objects[0].objects[1].objects[0].Data);
                CheckPwd.Compute();

                string decryptedPwdChk = TripleDESHelper.DESCBCDecryptor(CheckPwd.Key, CheckPwd.IV, f800001.objects[0].objects[1].Data);

                if (!decryptedPwdChk.StartsWith("password-check"))
                {

                    Console.WriteLine("Master password is wrong !");
                    return null;
                }

                query = "SELECT a11,a102 FROM nssPrivate";
                GetItemsFromQuery(dir, ref a11, ref a102, query);
                var decodedA11 = asn.Parse(a11);
                var entrySalt = decodedA11.objects[0].objects[0].objects[1].objects[0].Data;
                var cipherT = decodedA11.objects[0].objects[1].Data;
                if (Verbose)
                {
                    Console.WriteLine("Fetch Private key");
                }
                return decrypt3DES(item1, masterPwd, entrySalt, cipherT);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exeption:\n" + ex.Message);
                return null;

            }
        }
        /// <summary>
        /// Special thanks to:
        /// lclevy
        /// https://github.com/lclevy/firepwd/blob/master/firepwd.py
        /// </summary>
        /// <param name="globalSalt"></param>
        /// <param name="masterPwd"></param>
        /// <param name="entrySalt"></param>
        /// <param name="cipherT"></param>
        /// <returns>private key limit to 24 byte</returns>
        private byte[] decrypt3DES(byte[] globalSalt, string masterPwd, byte[] entrySalt, byte[] cipherT)
        {
            try
            {
                var sha1 = SHA1.Create("sha1");
                var hp = sha1.ComputeHash(globalSalt);
                Array.Resize(ref hp, 40);
                Array.Copy(entrySalt, 0, hp, 20, 20);

                var pes = entrySalt.Concat(Enumerable.Range(1, 20 - entrySalt.Length).Select(b => (byte)0).ToArray()).ToArray();
                Array.Resize(ref pes, 40);
                Array.Copy(entrySalt, 0, pes, 20, 20);
                var chp = sha1.ComputeHash(hp);
                var hmac = HMACSHA1.Create();
                hmac.Key = chp;
                var k1 = hmac.ComputeHash(pes);
                Array.Resize(ref pes, 20);

                var tk = hmac.ComputeHash(pes);
                Array.Resize(ref tk, 40);
                Array.Copy(entrySalt, 0, tk, 20, 20);
                var k2 = hmac.ComputeHash(tk);
                Array.Resize(ref k1, 40);
                Array.Copy(k2, 0, k1, 20, 20);
                var iv = k1.Skip(k1.Length - 8).ToArray();
                var key = k1.Take(24).ToArray();
                return TripleDESHelper.DESCBCDecryptorByte(key, iv, cipherT).Take(24).ToArray();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exeption:\n" + ex.Message);
                return null;
            }
        }

        private void GetItemsFromQuery(string dir, ref byte[] item1, ref byte[] item2, string query)
        {
            DataTable dt = new DataTable();

            var db_way = dir + "\\key4.db";
            var ConnectionString = "data source=" + db_way + ";New=True;UseUTF16Encoding=True";
            var sql = string.Format(query);
            using (SQLiteConnection connect = new SQLiteConnection(ConnectionString))
            {
                connect.Open();
                using (SQLiteCommand command = new SQLiteCommand(sql, connect))
                {
                    SQLiteDataAdapter adapter = new SQLiteDataAdapter(command);
                    adapter.Fill(dt);

                    int rows = dt.Rows.Count;
                    for (int i = 0; i < rows; i++)
                    {
                        Array.Resize(ref item2, ((byte[])dt.Rows[i][1]).Length);
                        Array.Copy((byte[])dt.Rows[i][1], item2, ((byte[])dt.Rows[i][1]).Length);
                        Array.Resize(ref item1, ((byte[])dt.Rows[i][0]).Length);
                        Array.Copy((byte[])dt.Rows[i][0], item1, ((byte[])dt.Rows[i][0]).Length);
                    }
                    adapter.Dispose();
                    connect.Close();
                }

            }
        }

        public byte[] CheckKey3DB(string filePath, string MasterPwd,bool Verbose)
        {
            try
            {
                Converts conv = new Converts();

                Asn1Der asn = new Asn1Der();
                BerkeleyDB db = new BerkeleyDB(Path.Combine(filePath, "key3.db"));
                if (Verbose)
                {
                    Console.WriteLine("Fetch data from key3.db file");
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
                    Console.WriteLine("GlobalSalt: " + GlobalSalt);
                }
                MozillaPBE CheckPwd = new MozillaPBE(conv.ConvertHexStringToByteArray(GlobalSalt), Encoding.ASCII.GetBytes(MasterPwd), conv.ConvertHexStringToByteArray(pwdCheck.EntrySalt));
                CheckPwd.Compute();
                string decryptedPwdChk = TripleDESHelper.DESCBCDecryptor(CheckPwd.Key, CheckPwd.IV, conv.ConvertHexStringToByteArray(pwdCheck.Passwordcheck));

                if (!decryptedPwdChk.StartsWith("password-check"))
                {

                    Console.WriteLine("Master password is wrong !");
                    return null;
                }

                // Get private key
                string f81 = (from p in db.Keys
                              where !p.Key.Equals("global-salt")
                              && !p.Key.Equals("Version")
                              && !p.Key.Equals("password-check")
                              select p.Value).FirstOrDefault().Replace("-", "");

                Asn1DerObject f800001 = asn.Parse(conv.ConvertHexStringToByteArray(f81));

                MozillaPBE CheckPrivateKey = new MozillaPBE(conv.ConvertHexStringToByteArray(GlobalSalt), Encoding.ASCII.GetBytes(MasterPwd), f800001.objects[0].objects[0].objects[1].objects[0].Data);
                CheckPrivateKey.Compute();

                byte[] decryptF800001 = TripleDESHelper.DESCBCDecryptorByte(CheckPrivateKey.Key, CheckPrivateKey.IV, f800001.objects[0].objects[1].Data);

                Asn1DerObject f800001deriv1 = asn.Parse(decryptF800001);

                Asn1DerObject f800001deriv2 = asn.Parse(f800001deriv1.objects[0].objects[2].Data);



                byte[] privateKey = new byte[24];

                if (f800001deriv2.objects[0].objects[3].Data.Length > 24)
                {
                    Array.Copy(f800001deriv2.objects[0].objects[3].Data, f800001deriv2.objects[0].objects[3].Data.Length - 24, privateKey, 0, 24);
                }
                else
                {
                    privateKey = f800001deriv2.objects[0].objects[3].Data;
                }
                return privateKey;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exeption:\n" + ex.Message);
                return null;

            }
        }
    }
}
