using System;
using System.Text;
using System.Windows;
using Microsoft.Win32;
using System.Security.Cryptography;
using System.IO;
using Ookii.Dialogs.Wpf;
using System.Drawing;

namespace EncryptionTool
{
    public partial class MainWindow : Window
    {
        private static MainWindow _instance = null;
        private static string filePath = null;
        private static string folderPath = null;
        private readonly static UTF8Encoding utf8 = new UTF8Encoding();
        public MainWindow()
        {
            _instance = this;
            InitializeComponent();
        }

        public static byte[] GenerateSalt()
        {
            byte[] data = new byte[32];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                for(int i = 0; i < 10; i++)
                {
                    rng.GetBytes(data);
                }
            }
            return data;
        }

        private void Encrypt_Click(object sender, RoutedEventArgs e)
        {
            if (filePath == null || folderPath == null)
            {
                MessageBox.Show("Please choose an input file and output folder.", "No paths provided", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            if (_instance.Key.Text == "")
            {
                MessageBox.Show("Please enter an Encryption/Decryption key", "No key provided", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            byte[] keyBytes = utf8.GetBytes(_instance.Key.Text);
            byte[] salt = GenerateSalt();
            Aes aes = Aes.Create();
            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(keyBytes, salt, 10000);
            aes.Key = key.GetBytes(aes.KeySize / 8);
            aes.IV = key.GetBytes(aes.BlockSize / 8);
            
            Console.WriteLine(folderPath + Path.GetFileName(filePath) + ".aes");

            if(File.Exists(folderPath + Path.GetFileName(filePath) + ".aes"))
            {
                MessageBoxResult result = MessageBox.Show("This file already exists, do you want to overwrite it?", "File already exists", MessageBoxButton.YesNo, MessageBoxImage.Exclamation);
                if(result == MessageBoxResult.No)
                {
                    return;
                }
            }

            FileStream encryptedFile = new FileStream(folderPath +Path.GetFileName(filePath) + ".aes", FileMode.Create);
            aes.Mode = CipherMode.CFB;
            encryptedFile.Write(salt, 0, salt.Length);
            CryptoStream cs = new CryptoStream(encryptedFile, aes.CreateEncryptor(), CryptoStreamMode.Write);
            FileStream fsIn = new FileStream(filePath, FileMode.Open);
            byte[] buffer = new byte[128];
            int read;

            try
            {
                while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cs.Write(buffer, 0, read);
                }
                fsIn.Close();
                MessageBox.Show("Successfully Encrypted File", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Could not encrypt file", "Error:", MessageBoxButton.OK, MessageBoxImage.Error);
                Console.WriteLine("Error: " + ex.Message);
            } finally
            {
                cs.Close();
                encryptedFile.Close();
            }
        }

        private void Decrypt_Click(object sender, RoutedEventArgs e)
        {
            if (filePath == null || folderPath == null)
            {
                MessageBox.Show("Please choose an input file and output folder.", "No paths provided", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            if (_instance.Key.Text == "")
            {
                MessageBox.Show("Please enter an Encryption/Decryption key", "No key provided", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            byte[] keyBytes = utf8.GetBytes(_instance.Key.Text);
            byte[] salt = new byte[32];

            FileStream encryptedFile = new FileStream(filePath, FileMode.Open);
            encryptedFile.Read(salt, 0, salt.Length);

            Aes aes = Aes.Create();
            aes.KeySize = 256;
            aes.BlockSize = 128;
            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(keyBytes, salt, 10000);
            aes.Key = key.GetBytes(aes.KeySize / 8);
            aes.IV = key.GetBytes(aes.BlockSize / 8);
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CFB;

            if (File.Exists(folderPath + Path.GetFileName(filePath) + ".txt"))
            {
                MessageBoxResult result = MessageBox.Show("This file already exists, do you want to overwrite it?", "File already exists", MessageBoxButton.YesNo, MessageBoxImage.Exclamation);
                if (result == MessageBoxResult.No)
                {
                    return;
                }
            }

            CryptoStream cs = new CryptoStream(encryptedFile, aes.CreateDecryptor(), CryptoStreamMode.Read);

            FileStream fsOut = new FileStream(folderPath + Path.GetFileName(filePath) + ".txt", FileMode.Create);

            byte[] buffer = new byte[1048576];
            int read;

            

            try
            {
                while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    fsOut.Write(buffer, 0, read);
                }
                MessageBox.Show("Successfully Decrypted File", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Could not decrypt file", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                Console.WriteLine("Error: " + ex.Message);
            }
            try
            {
                cs.Close();
            } catch (Exception ex)
            {
                Console.WriteLine("Error closing CryptoStream: " + ex.Message);
            }
            finally
            {
                fsOut.Close();
                encryptedFile.Close();
            }
        }

        private void InputFile_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                DefaultExt = ".txt|.aes",
                Filter = "Input files|*aes;*txt|Plain Text|*txt|Encrypted Files|*aes|All files|*"
            };
            Nullable<bool> result = openFileDialog.ShowDialog();
            if (result == true)
            {
                filePath = openFileDialog.FileName;
                _instance.InputFile.Content = Path.GetFileName(filePath);
            }
        }

        private void OutputFolder_Click(object sender, RoutedEventArgs e)
        {
            VistaFolderBrowserDialog dialog = new VistaFolderBrowserDialog();
            if(dialog.ShowDialog(this).GetValueOrDefault())
            {
                folderPath = dialog.SelectedPath + @"\";
                _instance.OutputFolder.Content = dialog.SelectedPath;
            }
        }
    }
}
