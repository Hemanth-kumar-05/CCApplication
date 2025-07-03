using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Encrypt
{
    public class IniFile
    {
        private string path;

        [DllImport("kernel32")]
        private static extern long WritePrivateProfileString(string section, string key, string val, string filePath);

        [DllImport("kernel32")]
        private static extern int GetPrivateProfileString(string section, string key, string def, StringBuilder retVal, int size, string filePath);

        public IniFile(string Path)
        {
            this.path = Path;
        }

        public void IniWriteValue(string Section, string Key, string Value)
        {
            IniFile.WritePrivateProfileString(Section, Key, Value, this.path);
        }

        public string IniReadValue(string Section, string Key)
        {
            StringBuilder stringBuilder = new StringBuilder(255);
            IniFile.GetPrivateProfileString(Section, Key, "", stringBuilder, 255, this.path);
            return stringBuilder.ToString();
        }        
    }
}