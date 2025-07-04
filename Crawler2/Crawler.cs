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
                Crawler.baseDirectory = Directory.GetCurrentDirectory() + Path.DirectorySeparatorChar;
                Crawler.FileName = Path.Combine(Crawler.baseDirectory, "crawlerCert.csv");
                StringBuilder stringBuilder = new StringBuilder();
                string text = string.Format("Certificate Type,File Name,Serial No,Cert URL,Implementation Date,Expiration Date,Days to Expire", new object[0]);
                bool flag = File.Exists(Crawler.FileName);
                if (flag)
                {
                    File.Delete(Crawler.FileName);
                }
                Crawler.Counter = 0;
                // Fix: Only 7 columns, so use 7 placeholders
                text = string.Format("{0},{1},{2},{3},{4},{5},{6}", new object[]
                {
                    "Certificate Type",
                    "File Name",
                    "Serial No",
                    "Cert URL",
                    "Implementation Date",
                    "Expiration Date",
                    "Days to Expire"
                });
                stringBuilder.AppendLine(text);
                NameValueCollection nameValueCollectionSection = Crawler.GetNameValueCollectionSection("appSettings", Path.Combine(Crawler.baseDirectory, "WinCert.config"));
                bool flag2 = nameValueCollectionSection[0] == "Y";
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
                    NameValueCollection nameValueCollectionSection2 = Crawler.GetNameValueCollectionSection("Certificates", Path.Combine(Crawler.baseDirectory, "WinCert.config"));
                    int i = 0;
                    while (i < nameValueCollectionSection2.Count)
                    {
                        string[] array = nameValueCollectionSection2[i].Split(new char[] { ',' });
                        if (array.Length == 0 || string.IsNullOrWhiteSpace(array[0]))
                        {
                            i++;
                            continue;
                        }
                        bool flag3 = array[0].Equals("p12");
                        if (flag3)
                        {
                            try
                            {
                                Crawler.Cert1(array[1], array[2], stringBuilder, Crawler.FileName, text);
                                goto IL_1BC;
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine("The Password is Invalid." + ex.Message, text);
                                goto IL_1BC;
                            }
                            goto IL_1BA;
                        }
                        goto IL_1BA;
                    IL_1BC:
                        i++;
                        continue;
                    IL_1BA:
                        Crawler.Cert1(array[1], array[0], stringBuilder, Crawler.FileName, text);
                        goto IL_1BC;
                    }
                }
                catch
                {
                    Console.WriteLine("Error reading app settings");
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

            // Load the config file as XML directly instead of using ConfigurationManager
            xmlDocument.Load(filePath);

            // Find the section node (e.g., appSettings or Certificates)
            XmlNode sectionNode = xmlDocument.SelectSingleNode($"//{section}");
            if (sectionNode != null)
            {
                foreach (XmlNode xmlNode2 in sectionNode.ChildNodes)
                {
                    if (xmlNode2.NodeType != XmlNodeType.Element) continue;
                    // Defensive: check for attribute count
                    if (xmlNode2.Attributes != null && xmlNode2.Attributes.Count >= 2)
                    {
                        nameValueCollection.Add(xmlNode2.Attributes[0].Value, xmlNode2.Attributes[1].Value);
                        bool flag = section == "Certificates";
                        if (flag && xmlNode2.Attributes.Count >= 3)
                        {
                            nameValueCollection.Add(xmlNode2.Attributes[0].Value, xmlNode2.Attributes[2].Value);
                        }
                    }
                }
            }
            return nameValueCollection;
        }

        private static void Cert1(string certpath, string certType, StringBuilder sb, string Filename, string newLine)
        {
            string[] files = Directory.GetFiles(certpath, "*." + certType, SearchOption.TopDirectoryOnly);
            int i = 0;
            while (i < files.Length)
            {
                string text = files[i];
                X509Certificate2Collection x509Certificate2Collection = new X509Certificate2Collection();
                bool flag = certType.Equals("p12", StringComparison.CurrentCultureIgnoreCase);
                if (flag)
                {
                    try
                    {
                        string text2 = Encryption.ReadConfig("DefaultNames", text, Crawler.baseDirectory);
                        bool flag2 = text2 == null;
                        if (flag2)
                        {
                        }
                        string text3 = Encryption.Decrypt(text2);
                        bool flag3 = text3 == null;
                        if (flag3)
                        {
                        }
                        x509Certificate2Collection.Import(text, text3, X509KeyStorageFlags.MachineKeySet);
                        goto IL_31C;
                    }
                    catch (Exception var_14_C1)
                    {
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
                    goto IL_157;
                }
                goto IL_157;
            IL_159:
                i++;
                continue;
            IL_157:
                bool flag4 = certType.Equals("jks", StringComparison.CurrentCultureIgnoreCase);
                if (flag4)
                {
                    try
                    {
                        string text4 = Encryption.ReadConfig("DefaultNames", text, Crawler.baseDirectory);
                        bool flag5 = text4 == null;
                        if (flag5)
                        {
                        }
                        string text5 = Encryption.Decrypt(text4);
                        bool flag6 = text5 == null;
                        if (flag6)
                        {
                        }
                        x509Certificate2Collection.Import(text, text5, X509KeyStorageFlags.MachineKeySet);
                        goto IL_31C;
                    }
                    catch (Exception var_20_1D9)
                    {
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
                try
                {
                    x509Certificate2Collection.Import(text);
                }
                catch
                {
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
                    }
                    catch
                    {
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
    }
}
