using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Encrypt
{
    public class Encryption
    {
        private static void Main(string[] args)
        {
            // Usage Example
            // app.exe <cet1_path> <cert1_pwd> <y/n> <cert2_path> <cert2_pwd> <y/n> ... <cetN_path> <certN_pwd> <n>
            if (args.Length < 3 || args.Length % 3 != 0)
            {
                Console.WriteLine("Usage: app.exe <cert_path> <cert_password> <y/n> ...");
                return;
            }

            for (int i = 0; i < args.Length; i += 3)
            {
                string certPath = args[i];
                string certPassword = args[i + 1];
                // bool nextCertFlag = args[i + 2].ToLower() == "y"; // Not used

                // Validate certificate path and its password
                X509Certificate2Collection x509Certificate2Collection = new X509Certificate2Collection();
                try
                {
                    x509Certificate2Collection.Import(certPath, certPassword, X509KeyStorageFlags.MachineKeySet);
                    string key = Encryption.Encrypt(certPassword);
                    Encryption.writeConfig(certPath, key);
                }
                catch
                {
                    // Handle the case where the certificate is invalid or the password is incorrect
                    string existingKey = Encryption.ReadConfig(certPath, "key", Directory.GetCurrentDirectory());
                    if (!string.IsNullOrEmpty(existingKey))
                    {
                        string decryptedPassword = Encryption.Decrypt(existingKey);
                        if (decryptedPassword != certPassword)
                        {
                            Encryption.writeConfig(certPath, Encryption.Encrypt(certPassword));
                        }
                    }
                    else
                    {
                        Encryption.writeConfig(certPath, Encryption.Encrypt(certPassword));
                    }
                }
            }   
        }


        public static string Encrypt(string clearText)
        {
            string password = "CitiPassword"; // Replace with your actual password
            byte[] bytes = Encoding.Unicode.GetBytes(clearText);
            using (Aes aes = Aes.Create())
            {
                Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, new byte[] { 73, 118, 97, 110, 32, 77, 101, 100, 118, 101, 100, 101, 118 });
                aes.Key = rfc2898DeriveBytes.GetBytes(32);
                aes.IV = rfc2898DeriveBytes.GetBytes(16);
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(bytes, 0, bytes.Length);
                        cryptoStream.Close();
                    }
                    clearText = Convert.ToBase64String(memoryStream.ToArray());
                }
                return clearText;
            }
        }

        public static string Decrypt(string cipherText)
        {
            string password = "CitiPassword";
            byte[] array = Convert.FromBase64String(cipherText);
            using (Aes aes = Aes.Create())
            {
                Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, new byte[] { 73, 118, 97, 110, 32, 77, 101, 100, 118, 101, 100, 101, 118 });
                aes.Key = rfc2898DeriveBytes.GetBytes(32);
                aes.IV = rfc2898DeriveBytes.GetBytes(16);
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(array, 0, array.Length);
                        cryptoStream.Close();
                    }
                    cipherText = Encoding.Unicode.GetString(memoryStream.ToArray());
                }
            }
            return cipherText;
        }

        public static string ReadConfig(string section, string key, string baseDirPath)
        {
            string text = string.Empty;
            bool flag = string.IsNullOrEmpty(baseDirPath);
            if (flag)
            {
                text = Directory.GetCurrentDirectory();
            }
            else
            {
                text = baseDirPath.Trim();
            }
            IniFile iniFile = new IniFile(Path.Combine(text, "Password_Encrypt.ini"));
            bool flag2 = !Directory.Exists(text);
            if (flag2)
            {
                Directory.CreateDirectory(text);
                iniFile.IniWriteValue("DefaultNames", "default1", "2");
                iniFile.IniWriteValue("DefaultNames", "default2", "1");
            }
            return iniFile.IniReadValue(section, key);
        }

        public static void writeConfig(string section, string key)
        {
            section = section.Replace('/', '\\');
            string currentDir = Directory.GetCurrentDirectory();
            IniFile iniFile = new IniFile(Path.Combine(currentDir, "Password_Encrypt.ini"));
            bool flag = !File.Exists(Path.Combine(currentDir, "Password_Encrypt.ini"));
            if (flag)
            {
                File.Create(Path.Combine(currentDir, "Password_Encrypt.ini")).Dispose();
            }
            iniFile.IniWriteValue("DefaultNames", section, key);
        }

        public static void WriteLog(string functionname, string msg, bool isError)
        {
            string currentDir = Directory.GetCurrentDirectory();
            string text = Path.Combine(currentDir, "crawler.log");
            if (isError)
            {
                msg = "in " + functionname + ". Error : " + msg;
            }
            else
            {
                msg = "in " + functionname + ". Info : " + msg;
            }
            if (!string.IsNullOrEmpty(text))
            {
                if (File.Exists(text))
                {
                    File.AppendAllText(text, DateTime.Now.ToString() + "--" + msg + Environment.NewLine);
                }
                else
                {
                    File.WriteAllText(text, DateTime.Now.ToString() + "--" + msg + Environment.NewLine);
                }
            }
        }
    }

}