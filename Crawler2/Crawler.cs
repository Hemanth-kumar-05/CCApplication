using Encrypt;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;

namespace Crawler2
{
    internal class Crawler
    {
        private class certDetails
        {
            public string ExpirationDate
            {
                get;
                set;
            }

            public string SimpleName
            {
                get;
                set;
            }

            public string EffectiveDate
            {
                get;
                set;
            }

            public bool PrivateKey
            {
                get;
                set;
            }

            public string SubjectName
            {
                get;
                set;
            }

            public string Issuer
            {
                get;
                set;
            }

            public string Subject
            {
                get;
                set;
            }

            public string Extensions
            {
                get;
                set;
            }

            public string FriendlyName
            {
                get;
                set;
            }

            public string NotBefore
            {
                get;
                set;
            }

            public string NotAfter
            {
                get;
                set;
            }

            public string SerialNumber
            {
                get;
                set;
            }

            public string filename
            {
                get;
                set;
            }
        }

        private static string FileName = "";

        private static int Counter = 0;

        private static string baseDirectory = string.Empty;

        private static void Main(string[] args)
        {
            try
            {
                // Console.WriteLine("[DEBUG] Main started. Current Directory: " + Directory.GetCurrentDirectory());
                Crawler.baseDirectory = Directory.GetCurrentDirectory() + Path.DirectorySeparatorChar;
                // Console.WriteLine("[DEBUG] baseDirectory set to: " + Crawler.baseDirectory);
                Crawler.FileName = Path.Combine(Crawler.baseDirectory, "crawlerCert.csv");
                // Console.WriteLine("[DEBUG] FileName set to: " + Crawler.FileName);
                StringBuilder stringBuilder = new StringBuilder();
                string text = string.Format("Certificate Type,File Name,Serial No,Cert URL,Implementation Date,Expiration Date,Days to Expire", new object[0]);
                bool flag = File.Exists(Crawler.FileName);
                // Console.WriteLine("[DEBUG] File.Exists(Crawler.FileName): " + flag);
                if (flag)
                {
                    File.Delete(Crawler.FileName);
                    // Console.WriteLine("[DEBUG] Deleted existing CSV file.");
                }
                Crawler.Counter = 0;
                text = string.Format("{0},{1},{2},{3},{4},{5},{6},{7}", new object[]
                {
                    "Index",
                    "Certificate Type",
                    "File Name",
                    "Serial No",
                    "Issuer",
                    "Implementation Date",
                    "Expiration Date",
                    "Days to Expire"
                });
                stringBuilder.AppendLine(text);
                NameValueCollection nameValueCollectionSection = Crawler.GetNameValueCollectionSection("appSettings", Path.Combine(Crawler.baseDirectory, "WinCert.config"));
                // Console.WriteLine("[DEBUG] Loaded appSettings section. Count: " + nameValueCollectionSection.Count);
                bool flag2 = nameValueCollectionSection[0] == "Y";
                // Console.WriteLine("[DEBUG] appSettings[0] == 'Y': " + flag2);
                if (flag2)
                {
                    X509Store computerCaStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
                    Crawler.saveCert(computerCaStore, ref stringBuilder, text);
                    computerCaStore = new X509Store(StoreName.AuthRoot, StoreLocation.LocalMachine);
                    Crawler.saveCert(computerCaStore, ref stringBuilder, text);
                    computerCaStore = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                    Crawler.saveCert(computerCaStore, ref stringBuilder, text);
                }
                try
                {
                    Crawler.baseDirectory = Directory.GetCurrentDirectory() + Path.DirectorySeparatorChar;
                    // Console.WriteLine("[DEBUG] baseDirectory (again) set to: " + Crawler.baseDirectory);
                    NameValueCollection nameValueCollectionSection2 = Crawler.GetNameValueCollectionSection("Certificates", Path.Combine(Crawler.baseDirectory, "WinCert.config"));
                    // Console.WriteLine("[DEBUG] Loaded Certificates section. Count: " + nameValueCollectionSection2.Count);
                    int i = 0;
                    while (i < nameValueCollectionSection2.Count)
                    {
                        // Console.WriteLine("[DEBUG] Processing Certificates entry index: " + i + " value: " + nameValueCollectionSection2[i]);
                        string[] array = nameValueCollectionSection2[i].Split(new char[] { ',' });
                        // Console.WriteLine("[DEBUG] Split array: " + string.Join("|", array));
                        if (array.Length == 0 || string.IsNullOrWhiteSpace(array[0]))
                        {
                            // Console.WriteLine("[DEBUG] Skipping empty or malformed entry at index: " + i);
                            i++;
                            continue;
                        }
                        bool flag3 = array[0].Equals("p12");
                        // Console.WriteLine("[DEBUG] array[0].Equals('p12'): " + flag3);
                        if (flag3)
                        {
                            try
                            {
                                if (array.Length > 2)
                                {
                                    // Console.WriteLine("[DEBUG] Calling Cert1 with: " + array[1] + ", " + array[2]);
                                    Crawler.Cert1(array[1], array[2], stringBuilder, Crawler.FileName, text);
                                }
                                else if (array.Length > 1)
                                {
                                    // Console.WriteLine("[DEBUG] Calling Cert1 with: " + array[1] + ", p12");
                                    Crawler.Cert1(array[1], "p12", stringBuilder, Crawler.FileName, text);
                                }
                                else
                                {
                                    // Console.WriteLine("[DEBUG] Not enough data in Certificates entry at index: " + i);
                                }
                                goto IL_1BC;
                            }
                            catch (Exception ex)
                            {
                                // Console.WriteLine("The Password is Invalid." + ex.Message, text);
                                goto IL_1BC;
                            }
                            goto IL_1BA;
                        }
                        goto IL_1BA;
                    IL_1BC:
                        i++;
                        continue;
                    IL_1BA:
                        // Console.WriteLine("[DEBUG] Calling Cert1 (fallback) with: " + array[1] + ", " + array[0]);
                        Crawler.Cert1(array[1], array[0], stringBuilder, Crawler.FileName, text);
                        goto IL_1BC;
                    }
                }
                catch (Exception ex)
                {
                    // Console.WriteLine("[DEBUG] Error reading app settings: " + ex.Message);
                }
                Console.WriteLine("Certificate Extraction Successful");
            }
            catch (Exception ex2)
            {
                Console.WriteLine("Error:" + ex2.Message);
            }
        }

        private static NameValueCollection GetNameValueCollectionSection(string section, string filePath)
        {
            XmlDocument xmlDocument = new XmlDocument();
            NameValueCollection nameValueCollection = new NameValueCollection();
            Configuration configuration = ConfigurationManager.OpenMappedExeConfiguration(new ExeConfigurationFileMap
            {
                ExeConfigFilename = filePath
            }, ConfigurationUserLevel.None);
            string rawXml = configuration.GetSection(section).SectionInformation.GetRawXml();
            // Console.WriteLine("[DEBUG] Raw XML for section '" + section + "': " + rawXml);
            xmlDocument.LoadXml(rawXml);
            XmlNode xmlNode = xmlDocument.ChildNodes[0];
            foreach (XmlNode xmlNode2 in xmlNode)
            {
                nameValueCollection.Add(xmlNode2.Attributes[0].Value, xmlNode2.Attributes[1].Value);
                bool flag = section == "Certificates";
                if (flag)
                {
                    nameValueCollection.Add(xmlNode2.Attributes[0].Value, xmlNode2.Attributes[2].Value);
                }
            }
            return nameValueCollection;
        }

        private static void Cert1(string certpath, string certType, StringBuilder sb, string Filename, string newLine)
        {
            // Console.WriteLine("[DEBUG] Cert1 called with certpath: " + certpath + ", certType: " + certType);
            string[] files = Directory.GetFiles(certpath, "*." + certType, SearchOption.TopDirectoryOnly);
            // Console.WriteLine("[DEBUG] Found files: " + string.Join(", ", files));
            int i = 0;
            while (i < files.Length)
            {
                string text = files[i];
                // Normalize all paths to use backslashes to match what Encryption stores in .ini file
                text = text.Replace('/', '\\');
                // Console.WriteLine("[DEBUG] Processing file (normalized): " + text);
                X509Certificate2Collection x509Certificate2Collection = new X509Certificate2Collection();
                // Check if this is a password-protected certificate format
                bool flag = IsPasswordProtectedFormat(certType);
                if (flag)
                {
                    try
                    {
                        // Console.WriteLine("[DEBUG] Reading config for: " + text);
                        string text2 = Encryption.ReadConfig("DefaultNames", text, Crawler.baseDirectory);
                        // Console.WriteLine("[DEBUG] ReadConfig returned: " + text2);
                        bool flag2 = text2 == null;
                        if (flag2)
                        {
                            // Console.WriteLine("[DEBUG] text2 is null");
                        }
                        string text3 = Encryption.Decrypt(text2);
                        // Console.WriteLine("[DEBUG] Decrypt returned: " + text3);
                        bool flag3 = text3 == null;
                        if (flag3)
                        {
                            // Console.WriteLine("[DEBUG] text3 is null");
                        }
                        x509Certificate2Collection.Import(text, text3, X509KeyStorageFlags.MachineKeySet);
                        // Console.WriteLine("[DEBUG] Certificate imported successfully.");
                        goto IL_31C;
                    }
                    catch (Exception var_14_C1)
                    {
                        // Console.WriteLine("[DEBUG] Exception in Cert1 (password-protected): " + var_14_C1.Message);
                        newLine = string.Format("{0},{1},{2},{3},{4},{5},{6},{7}", new object[]
                        {
                            ++Crawler.Counter,
                            Crawler.AddEscapeSequenceInCsvField(certType),
                            Crawler.AddEscapeSequenceInCsvField(text),
                            Crawler.AddEscapeSequenceInCsvField("CERT Password is Not Valid"),
                            Crawler.AddEscapeSequenceInCsvField("NA"),
                            Crawler.AddEscapeSequenceInCsvField("NA"),
                            Crawler.AddEscapeSequenceInCsvField("NA"),
                            Crawler.AddEscapeSequenceInCsvField("NA")
                        });
                        sb.AppendLine(newLine);
                        File.WriteAllText(Filename, sb.ToString());
                        goto IL_159;
                    }
                }
                else
                {
                    // For non-password-protected certificates (cer, crt, pem, etc.)
                    try
                    {
                        // Console.WriteLine("[DEBUG] Importing certificate without password: " + text);
                        x509Certificate2Collection.Import(text);
                        goto IL_31C;
                    }
                    catch (Exception ex)
                    {
                        // Console.WriteLine("[DEBUG] Exception importing certificate without password: " + ex.Message);
                        newLine = string.Format("{0},{1},{2},{3},{4},{5},{6},{7}", new object[]
                        {
                            ++Crawler.Counter,
                            Crawler.AddEscapeSequenceInCsvField(certType),
                            Crawler.AddEscapeSequenceInCsvField(text),
                            Crawler.AddEscapeSequenceInCsvField("Invalid Certificate"),
                            Crawler.AddEscapeSequenceInCsvField("NA"),
                            Crawler.AddEscapeSequenceInCsvField("NA"),
                            Crawler.AddEscapeSequenceInCsvField("NA"),
                            Crawler.AddEscapeSequenceInCsvField("NA")
                        });
                        sb.AppendLine(newLine);
                        File.WriteAllText(Filename, sb.ToString());
                        goto IL_159;
                    }
                }
            IL_159:
                i++;
                continue;
            IL_31C:
                X509Certificate2Enumerator enumerator = x509Certificate2Collection.GetEnumerator();
                while (enumerator.MoveNext())
                {
                    X509Certificate2 current = enumerator.Current;
                    Crawler.certDetails certDetails = new Crawler.certDetails();
                    certDetails.Issuer = current.Issuer;
                    certDetails.Extensions = current.Extensions.ToString();
                    certDetails.NotBefore = current.NotBefore.ToShortDateString();
                    certDetails.NotAfter = current.NotAfter.ToShortDateString();
                    certDetails.SerialNumber = current.SerialNumber;
                    certDetails.filename = text;
                    TimeSpan timeSpan = current.NotAfter.Subtract(DateTime.Now);
                    try
                    {
                        newLine = string.Format("{0},{1},{2},{3},{4},{5},{6},{7}", new object[]
                        {
                            ++Crawler.Counter,
                            Crawler.AddEscapeSequenceInCsvField(certType),
                            Crawler.AddEscapeSequenceInCsvField(certDetails.filename),
                            Crawler.AddEscapeSequenceInCsvField(certDetails.SerialNumber),
                            Crawler.AddEscapeSequenceInCsvField(certDetails.Issuer),
                            Crawler.AddEscapeSequenceInCsvField(certDetails.NotBefore),
                            Crawler.AddEscapeSequenceInCsvField(certDetails.NotAfter),
                            Crawler.AddEscapeSequenceInCsvField(timeSpan.Days.ToString())
                        });
                        sb.AppendLine(newLine);
                        File.WriteAllText(Filename, sb.ToString());
                        // Console.WriteLine("[DEBUG] Wrote certificate details to CSV.");
                    }
                    catch (Exception ex)
                    {
                        // Console.WriteLine("[DEBUG] Exception writing certificate details: " + ex.Message);
                        newLine = string.Format("{0},{1},{2},{3},{4},{5},{6},{7}", new object[]
                        {
                            ++Crawler.Counter,
                            Crawler.AddEscapeSequenceInCsvField(certType),
                            Crawler.AddEscapeSequenceInCsvField(certDetails.filename),
                            Crawler.AddEscapeSequenceInCsvField("NA"),
                            Crawler.AddEscapeSequenceInCsvField("NA"),
                            Crawler.AddEscapeSequenceInCsvField("NA"),
                            Crawler.AddEscapeSequenceInCsvField("NA"),
                            Crawler.AddEscapeSequenceInCsvField("NA")
                        });
                        sb.AppendLine(newLine);
                        File.WriteAllText(Filename, sb.ToString());
                    }
                }
                goto IL_159;
            }
        }

        private static void saveCert(X509Store computerCaStore, ref StringBuilder csv, string newLine)
        {
            try
            {
                computerCaStore.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certificates = computerCaStore.Certificates;
                List<Crawler.certDetails> list = new List<Crawler.certDetails>();
                X509Certificate2Enumerator enumerator = certificates.GetEnumerator();
                while (enumerator.MoveNext())
                {
                    X509Certificate2 current = enumerator.Current;
                    Crawler.certDetails certDetails = new Crawler.certDetails();
                    certDetails.ExpirationDate = current.GetExpirationDateString();
                    certDetails.Issuer = current.Issuer;
                    certDetails.EffectiveDate = current.GetEffectiveDateString();
                    certDetails.SubjectName = current.SubjectName.Name;
                    certDetails.SerialNumber = current.SerialNumber.ToString();
                    TimeSpan timeSpan = current.NotAfter.Subtract(DateTime.Now);
                    try
                    {
                        newLine = string.Format("{0},{1},{2},{3},{4},{5},{6},{7}", new object[]
                        {
                            ++Crawler.Counter,
                            Crawler.AddEscapeSequenceInCsvField("Store Certficate"),
                            Crawler.AddEscapeSequenceInCsvField(computerCaStore.Name),
                            Crawler.AddEscapeSequenceInCsvField(certDetails.SerialNumber),
                            Crawler.AddEscapeSequenceInCsvField(certDetails.Issuer),
                            Crawler.AddEscapeSequenceInCsvField(certDetails.EffectiveDate),
                            Crawler.AddEscapeSequenceInCsvField(certDetails.ExpirationDate),
                            Crawler.AddEscapeSequenceInCsvField(timeSpan.Days.ToString())
                        });
                        csv.AppendLine(newLine);
                        list.Add(certDetails);
                    }
                    catch
                    {
                        newLine = string.Format("{0},{1},{2},{3},{4},{5},{6},{7}", new object[]
                        {
                            ++Crawler.Counter,
                            Crawler.AddEscapeSequenceInCsvField("Store Certficate"),
                            Crawler.AddEscapeSequenceInCsvField(computerCaStore.Name),
                            Crawler.AddEscapeSequenceInCsvField("NA"),
                            Crawler.AddEscapeSequenceInCsvField("NA"),
                            Crawler.AddEscapeSequenceInCsvField("NA"),
                            Crawler.AddEscapeSequenceInCsvField("NA"),
                            Crawler.AddEscapeSequenceInCsvField("NA")
                        });
                        csv.AppendLine(newLine);
                        list.Add(certDetails);
                    }
                }
            }
            catch (Exception var_9_1F9)
            {
            }
            finally
            {
                computerCaStore.Close();
            }
        }

        private static string AddEscapeSequenceInCsvField(string ValueToEscape)
        {
            bool flag = ValueToEscape.Contains(",");
            string result;
            if (flag)
            {
                result = ValueToEscape.Replace(',', ' ');
            }
            else
            {
                result = ValueToEscape;
            }
            return result;
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

        private static bool IsPasswordProtectedFormat(string certType)
        {
            if (string.IsNullOrEmpty(certType))
                return false;

            string lowerCertType = certType.ToLowerInvariant();
            return lowerCertType == "p12" ||
                   lowerCertType == "pfx" ||
                   lowerCertType == "pkcs12" ||
                   lowerCertType == "jks" ||
                   lowerCertType == "jceks" ||
                   lowerCertType == "bks" ||
                   lowerCertType == "bcfks" ||
                   lowerCertType == "kdb";
        }
    }
}