using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;

namespace RSAKeyGenerator
{
    public partial class MainWindow : Window
    {
        private const int KeySize = 4096;
        private const string PrivateKeyFileName = "private_key.enc";
        private const string PublicKeyFileName = "public_key.bin";

        public MainWindow()
        {
            InitializeComponent();
        }

        private async void GenerateKeys_Click(object sender, RoutedEventArgs e)
        {
            string pin = PinBox.Password;

            if (string.IsNullOrWhiteSpace(pin))
            {
                StatusText.Text = "PIN cannot be empty.";
                return;
            }

            try
            {
                GenerateKeysButton.IsEnabled = false;
                StatusText.Text = "Generating keys...";

                await Task.Run(() => GenerateAndSaveKeys(pin));
            }
            catch (Exception ex)
            {
                StatusText.Text = $"Error: {ex.Message}";
            }
            finally
            {
                GenerateKeysButton.IsEnabled = true;
            }
        }

        private void GenerateAndSaveKeys(string pin)
        {
            try
            {
                using var rsa = RSA.Create(KeySize);
                byte[] privateKey = rsa.ExportRSAPrivateKey();
                byte[] publicKey = rsa.ExportRSAPublicKey();

                byte[] encryptedPrivateKey = EncryptPrivateKey(privateKey, pin);

                SaveKeys(encryptedPrivateKey, publicKey);

                Dispatcher.Invoke(() => StatusText.Text = "Keys generated and saved to files.");
            }
            catch (Exception e)
            {
                Dispatcher.Invoke(() => StatusText.Text = $"Error: {e.Message}");
                throw;
            }
        }

        private void SaveKeys(byte[] encryptedPrivateKey, byte[] publicKey)
        {
            string pendrive = DriveInfo.GetDrives()
                                       .Where(static d => d.DriveType == DriveType.Removable && d.IsReady)
                                       .Select(static d => d.RootDirectory.FullName)
                                       .FirstOrDefault()
                                       ?? throw new InvalidOperationException("Pendrive not detected.");
            try
            {
                string privateKeyPath = Path.Combine(pendrive, PrivateKeyFileName);

                File.WriteAllBytes(privateKeyPath, encryptedPrivateKey);
                File.WriteAllBytes(PublicKeyFileName, publicKey);

                Dispatcher.Invoke(() => StatusText.Text = "Keys generated and saved successfully.");
            }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() => StatusText.Text = $"Error saving keys: {ex.Message}");
                throw; 
            }
        }

        private static byte[] EncryptPrivateKey(byte[] privateKey, string pin)
        {
            byte[] pinBytes = Encoding.UTF8.GetBytes(pin);
            byte[] pinHash;

            pinHash = SHA256.HashData(pinBytes);

            using var aes = Aes.Create();
            aes.Key = pinHash;
            aes.GenerateIV();
            byte[] iv = aes.IV;

            using var ms = new MemoryStream();
            ms.Write(iv, 0, iv.Length);
            using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cs.Write(privateKey, 0, privateKey.Length);
            }

            return ms.ToArray();
        }
    }
}