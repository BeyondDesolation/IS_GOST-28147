using Microsoft.Win32;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows;

namespace D.ISlab2
{
    public partial class MainWindow : Window
    {
        private string _keyStr = "I Love GoldenGlow";
        private byte[] _data;

        public MainWindow()
        {
            InitializeComponent();
        }

        private void bEncrypt_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(tbText.Text))
            {
                MessageBox.Show("Текст пуст", "Ой", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            SHA512 sha = SHA512.Create();
            var keyStr = string.IsNullOrEmpty(tbKey.Text) ? _keyStr : tbKey.Text;

            var key = sha.ComputeHash(Encoding.UTF8.GetBytes(keyStr)).Take(32).ToArray();
            
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            var IV = new byte[8];
            rng.GetBytes(IV);

            var gost = new GOST28147(key, IV);

            var cipherText = gost.Encrypt(Encoding.UTF8.GetBytes(tbText.Text));
            _data = new byte[cipherText.Length + IV.Length];

            Array.Copy(IV, _data, IV.Length);
            Array.Copy(cipherText, 0, _data, IV.Length, cipherText.Length);

            tbText.Text = Encoding.UTF8.GetString(_data);
        }

        private void bDecrypt_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(tbText.Text))
            {
                MessageBox.Show("Текст пуст", "Ой", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            SHA512 sha = SHA512.Create();
            var keyStr = string.IsNullOrEmpty(tbKey.Text) ? _keyStr : tbKey.Text;

            var key = sha.ComputeHash(Encoding.UTF8.GetBytes(keyStr)).Take(32).ToArray();
            byte[] data = _data;

            var IV = new byte[8];
            byte[] cipherText;
            try
            {
                cipherText = new byte[data.Length - IV.Length];
            }
            catch (Exception ex)
            {
                return;
            }


            Array.Copy(data, IV, IV.Length);
            Array.Copy(data, IV.Length, cipherText, 0, cipherText.Length);

            var gost = new GOST28147(key, IV);
            var plainText = gost.Decrypt(cipherText);

            tbText.Text = Encoding.UTF8.GetString(plainText);
            _data = plainText;
        }

        private void menuAboutProgramm_Click(object sender, RoutedEventArgs e)
        {
        }

     
        private void bSave_Click(object sender, RoutedEventArgs e)
        {
            var ofd = new OpenFileDialog();
            if(ofd.ShowDialog() == true)
            {
                var file = ofd.FileName;

                using(var fs = new System.IO.FileStream(file, System.IO.FileMode.Create))
                {
                    fs.Write(_data);
                }
            }
        }

        private void bLoad_Click(object sender, RoutedEventArgs e)
        {
            var ofd = new OpenFileDialog();
            if (ofd.ShowDialog() == true)
            {
                var file = ofd.FileName;

                using (var fs = new System.IO.FileStream(file, System.IO.FileMode.Open))
                {
                    _data = new byte[fs.Length];
                    fs.Read(_data, 0, _data.Length);
                    tbText.Text = Encoding.UTF8.GetString(_data);
                }
            }
        }

        private void bLoadKey_Click(object sender, RoutedEventArgs e)
        {
            var ofd = new OpenFileDialog();
            if (ofd.ShowDialog() == true)
            {
                var file = ofd.FileName;

                using (var fs = new System.IO.FileStream(file, System.IO.FileMode.Open))
                {
                    byte[] keyBuffer = new byte[fs.Length];

                    fs.Read(keyBuffer, 0, keyBuffer.Length);
                    _keyStr = Encoding.UTF8.GetString(keyBuffer);
                    tbKey.Text = _keyStr;

                }
            }
        }
    }
}
