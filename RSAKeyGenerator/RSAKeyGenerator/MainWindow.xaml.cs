using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Threading;

namespace RSAKeyGenerator
{
    public partial class MainWindow : Window
    {
        /// <summary>
        /// Constant defining the RSA key size (4096 bits).
        /// </summary>
        private const int KeySize = 4096;

        /// <summary>
        /// File name for the encrypted private key.
        /// </summary>
        private const string PrivateKeyFileName = "private_key.enc";

        /// <summary>
        /// File name for the public key.
        /// </summary>
        private const string PublicKeyFileName = "public_key.bin";

        private readonly DispatcherTimer _driveCheckTimer;

        /// <summary>
        /// Initializes a new instance of the <see cref="MainWindow"/> class.
        /// Sets up UI components and starts the pendrive detection timer.
        /// </summary>
        public MainWindow()
        {
            InitializeComponent();

            _driveCheckTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(1) // Check every 1 second
            };
            _driveCheckTimer.Tick += DriveCheckTimer_Tick;
            _driveCheckTimer.Start(); // Start the timer

            // Initialize the pendrive status check on startup
            UpdatePendriveStatus();
        }

        /// <summary>
        /// Timer tick event handler to check pendrive status periodically.
        /// </summary>
        /// <param name="sender">Event sender.</param>
        /// <param name="e">Event arguments.</param>
        private void DriveCheckTimer_Tick(object sender, EventArgs e)
        {
            // Check the status of the pendrive and update the status label
            UpdatePendriveStatus();
        }

        /// <summary>
        /// Checks for the presence of a removable drive (pendrive) and updates the UI accordingly.
        /// </summary>
        private void UpdatePendriveStatus()
        {
            // Try to find the first removable drive that is ready
            string pendrive = DriveInfo.GetDrives()
                                       .Where(static d => d.DriveType == DriveType.Removable && d.IsReady)
                                       .Select(static d => d.RootDirectory.FullName)
                                       .FirstOrDefault();

            // If pendrive is found, update status accordingly
            if (!string.IsNullOrEmpty(pendrive))
            {
                StatusText.Text = $"Pendrive detected at: {pendrive}";
                GenerateKeysButton.IsEnabled = true; // Enable the key generation button
            }
            else
            {
                StatusText.Text = "No pendrive detected.";
                GenerateKeysButton.IsEnabled = false; // Disable the button if no pendrive
            }
        }

        /// <summary>
        /// Handles the click event for the "GenerateKeys" button, triggers RSA key generation asynchronously.
        /// </summary>
        /// <param name="sender">Event sender.</param>
        /// <param name="e">Event arguments.</param>
        private async void GenerateKeys_Click(object sender, RoutedEventArgs e)
        {
            // Get the PIN entered by the user
            string pin = PinBox.Password;

            // If the PIN is empty, show an error message and return
            if (string.IsNullOrWhiteSpace(pin))
            {
                StatusText.Text = "PIN cannot be empty.";
                return;
            }

            try
            {
                // Disable the button to prevent multiple clicks while generating keys
                GenerateKeysButton.IsEnabled = false;
                StatusText.Text = "Generating keys...";

                // Run key generation and saving asynchronously in a separate thread
                await Task.Run(() => GenerateAndSaveKeys(pin));
            }
            catch (Exception ex)
            {
                // If an error occurs, display the error message
                StatusText.Text = $"Error: {ex.Message}";
            }
            finally
            {
                // Re-enable the button once the process is done
                GenerateKeysButton.IsEnabled = true;
            }
        }

        /// <summary>
        /// Generates RSA key pair, encrypts the private key using the PIN, and saves the keys to files.
        /// </summary>
        /// <param name="pin">PIN used to encrypt the private key.</param>
        private void GenerateAndSaveKeys(string pin)
        {
            try
            {
                // Create an RSA object with the specified key size (4096 bits)
                using var rsa = RSA.Create(KeySize);

                // Export the private and public RSA keys as byte arrays
                byte[] privateKey = rsa.ExportRSAPrivateKey();
                byte[] publicKey = rsa.ExportRSAPublicKey();

                // Encrypt the private key with the provided PIN
                byte[] encryptedPrivateKey = EncryptPrivateKey(privateKey, pin);

                // Save the encrypted private key and public key to files
                SaveKeys(encryptedPrivateKey, publicKey);

                // Update the status text on the UI thread
                Dispatcher.Invoke(() => StatusText.Text = "Keys generated and saved to files.");
            }
            catch (Exception e)
            {
                Dispatcher.Invoke(() => StatusText.Text = $"Error: {e.Message}");
                throw;
            }
        }

        /// <summary>
        /// Saves the encrypted private key and public key to appropriate files on the pendrive and local storage.
        /// </summary>
        /// <param name="encryptedPrivateKey">Encrypted private key bytes.</param>
        /// <param name="publicKey">Public key bytes.</param>
        /// <exception cref="InvalidOperationException">Thrown if pendrive is not detected.</exception>
        private void SaveKeys(byte[] encryptedPrivateKey, byte[] publicKey)
        {
            // Find the first removable drive (e.g., USB stick)
            string pendrive = DriveInfo.GetDrives()
                                       .Where(static d => d.DriveType == DriveType.Removable && d.IsReady)
                                       .Select(static d => d.RootDirectory.FullName)
                                       .FirstOrDefault()
                                       ?? throw new InvalidOperationException("Pendrive not detected.");
            try
            {
                // Path to save the encrypted private key on the pendrive
                string privateKeyPath = Path.Combine(pendrive, PrivateKeyFileName);

                // Write the encrypted private key and public key to files
                File.WriteAllBytes(privateKeyPath, encryptedPrivateKey);
                File.WriteAllBytes(PublicKeyFileName, publicKey);

                // Update the status text on the UI thread
                Dispatcher.Invoke(() => StatusText.Text = "Keys generated and saved successfully.");
            }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() => StatusText.Text = $"Error saving keys: {ex.Message}");
                throw; 
            }
        }

        /// <summary>
        /// Encrypts the private key using AES encryption with a key derived from the provided PIN and a random salt.
        /// </summary>
        /// <param name="privateKey">The raw private key bytes to encrypt.</param>
        /// <param name="pin">The PIN used to derive the encryption key.</param>
        /// <returns>Byte array containing the IV, salt, and encrypted private key data.</returns>
        private static byte[] EncryptPrivateKey(byte[] privateKey, string pin)
        {
            // Generate a random salt (16 bytes)
            byte[] salt = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt); // Fill the salt with random bytes
            }

            // Convert the PIN to a byte array
            byte[] pinBytes = Encoding.UTF8.GetBytes(pin);
            byte[] pinHash;

            // Hash the PIN concatenated with the salt using SHA256
            using (var sha256 = SHA256.Create())
            {
                // Concatenate the PIN bytes with the salt
                byte[] pinWithSalt = pinBytes.Concat(salt).ToArray();
                pinHash = sha256.ComputeHash(pinWithSalt); // Compute the hash
            }

            // Create an AES encryption instance
            using var aes = Aes.Create();
            aes.Key = pinHash; // Use the hashed PIN (with salt) as the AES key
            aes.GenerateIV(); // Generate a random initialization vector (IV)
            byte[] iv = aes.IV; 

            // Create a memory stream to write the encrypted data
            using var ms = new MemoryStream();
            ms.Write(iv, 0, iv.Length); // Write the IV at the beginning of the stream
            ms.Write(salt, 0, salt.Length); // Write the salt after the IV

            // Create a CryptoStream to encrypt the private key
            using (var cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                cs.Write(privateKey, 0, privateKey.Length); // Encrypt the private key and write it to the stream
            }

            // Return the encrypted private key, IV, and salt as a byte array
            return ms.ToArray(); // The final result is the byte array of encrypted data
        }
    }
}