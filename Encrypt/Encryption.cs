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
                bool nextCertFlag = args[i + 2].ToLower() == "y";

                // Validate certificate path and its password
                Console.WriteLine("Validating Certificate");
                X509Certificate2Collection x509Certificate2Collection = new X509Certificate2Collection();
                try
                {
                    x509Certificate2Collection.Import(certPath, certPassword, X509KeyStorageFlags.MachineKeySet);
                    string key = Encryption.Encrypt(certPassword);
                    // Console.WriteLine($"Certificate {certPath} is valid. Writing encrypted password to config.");
                    Encryption.writeConfig(certPath, key);
                }
                catch
                {
                    // Handle the case where the certificate is invalid or the password is incorrect
                    // Update the password in the config file
                    string existingKey = Encryption.ReadConfig(certPath, "key", Directory.GetCurrentDirectory());
                    if (!string.IsNullOrEmpty(existingKey))
                    {
                        string decryptedPassword = Encryption.Decrypt(existingKey);
                        if (decryptedPassword != certPassword)
                        {
                            Console.WriteLine("Updating password");
                            Encryption.writeConfig(certPath, Encryption.Encrypt(certPassword));
                        }
                    }
                    else
                    {
                        Console.WriteLine("No existing key found. Writing new key.");
                        Encryption.writeConfig(certPath, Encryption.Encrypt(certPassword));
                    }
                }
            }   
        }


        public static string Encrypt(string clearText)
        {
            string password = "securepassword"; // Replace with your actual password
            byte[] bytes = Encoding.Unicode.GetBytes(clearText);
            using (Aes aes = Aes.Create())
            {
                Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, new byte[] { 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122 });
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
            string password = "securepassword";
            byte[] array = Convert.FromBase64String(cipherText);
            using (Aes aes = Aes.Create())
            {
                Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, new byte[] { 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122 });
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
            text = baseDirPath.Trim();
            IniFile iniFile = new IniFile(text + "Password_Encrypt.ini");
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
            string currentDir = Directory.GetCurrentDirectory();
            IniFile iniFile = new IniFile(Path.Combine(currentDir, "Password_Encrypt.ini"));
            bool flag = !File.Exists(Path.Combine(currentDir, "Password_Encrypt.ini"));
            if (flag)
            {
                File.Create(Path.Combine(currentDir, "Password_Encrypt.ini")).Dispose();
            }
            Console.WriteLine($"Writing key {key} to section {section} in {currentDir}\\Password_Encrypt.ini");
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
            msg = "in " + functionname + ". Info : " + msg;
            bool flag = string.IsNullOrEmpty(text);
            if (!flag)
            {
                bool flag2 = File.Exists(text);
                if (flag2)
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