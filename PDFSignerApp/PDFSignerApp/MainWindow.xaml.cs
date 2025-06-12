using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using Microsoft.Win32;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;

namespace PDFSignerApp
{
    public partial class MainWindow : Window
    {
        /// <summary>
        /// Timer that periodically checks for the presence of a USB drive.
        /// </summary>
        private readonly DispatcherTimer _driveCheckTimer;

        /// <summary>
        /// Stores the current detected USB drive path. Empty if no drive is detected.
        /// </summary>
        private string _currentPendrivePath = string.Empty;

        /// <summary>
        /// Initializes a new instance of the <see cref="MainWindow"/> class.
        /// Sets up the UI and starts the USB drive detection timer.
        /// </summary>
        public MainWindow()
        {
            InitializeComponent();

            btnSign.IsEnabled = false;
            btnVerify.IsEnabled = true;

            // Initialize the drive check timer to check every second
            _driveCheckTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(1)
            };
            _driveCheckTimer.Tick += DriveCheckTimer_Tick;
            _driveCheckTimer.Start();

            // Initial check for pendrive status
            UpdatePendriveStatus();
        }

        /// <summary>
        /// Event handler for the drive check timer tick.
        /// Checks for the presence of a USB drive and updates the UI accordingly.
        /// </summary>
        private void DriveCheckTimer_Tick(object sender, EventArgs e)
        {
            UpdatePendriveStatus();
        }

        /// <summary>
        /// Checks for the presence of a USB drive and updates the status text.
        /// If a drive is detected, it checks for the presence of a private key file.
        /// If the private key file is found, it enables the sign button.
        /// If no drive is detected or the private key file is missing, it disables the sign button.
        /// </summary>
        private void UpdatePendriveStatus()
        {
            // Find the first removable drive that is ready (i.e., a USB pendrive)
            string pendrive = DriveInfo.GetDrives()
                .Where(d => d.DriveType == DriveType.Removable && d.IsReady)
                .Select(d => d.RootDirectory.FullName)
                .FirstOrDefault();

            // If a pendrive is detected, check for the private key file
            if (!string.IsNullOrEmpty(pendrive))
            {
                StatusText.Foreground = Brushes.Green;
                StatusText.Text = $"Pendrive detected at: {pendrive}";

                string privateKeyPath = System.IO.Path.Combine(pendrive, "private_key.enc");
                _currentPendrivePath = pendrive;

                if (File.Exists(privateKeyPath))
                {
                    StatusText.Text = $"Pendrive with private key detected at: {pendrive}";
                    if (txtFilePath.Text.Length > 0)
                        btnSign.IsEnabled = true;
                }
                else
                {
                    StatusText.Foreground = Brushes.Red;
                    StatusText.Text = $"Pendrive detected but no private key found at: {privateKeyPath}";
                }
            }
            else
            {
                StatusText.Foreground = Brushes.Red;
                StatusText.Text = "No pendrive detected.";
                btnSign.IsEnabled = false;
            }
        }

        /// <summary>
        /// Event handler for the "Select File" button click.
        /// Opens a file dialog to select a PDF file for signing.
        /// If a file is selected, it updates the file path text box and enables the sign button.
        /// If no file is selected, it updates the status text accordingly and disables the sign button.
        /// </summary>
        private void btnSelectFile_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Filter = "PDF Files (*.pdf)|*.pdf",
                Title = "Select PDF File"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                txtFilePath.Text = openFileDialog.FileName;
                StatusText.Foreground = Brushes.Green;
                StatusText.Text = "PDF file selected!";
                btnSign.IsEnabled = true;
            }
            else
            {
                StatusText.Foreground = Brushes.Red;
                StatusText.Text = "No file selected.";
                btnSign.IsEnabled = false;
            }
        }

        /// <summary>
        /// Event handler for the "Sign PDF" button click.
        /// Validates the PIN input, attempts to load the private key and certificate associated with the user's smart card or keystore,
        /// and signs the selected PDF document using the specified credentials.
        /// Provides visual feedback to the user about the progress and result of the operation.
        /// </summary>
        /// <param name="sender">The source of the event, typically the Sign button.</param>
        /// <param name="e">Event arguments associated with the button click.</param>
        private void btnSign_Click(object sender, RoutedEventArgs e)
        {
            string pin = PinBox.Password;

            if (string.IsNullOrWhiteSpace(pin))
            {
                StatusText.Foreground = Brushes.Red;
                StatusText.Text = "PIN cannot be empty.";
                return;
            }

            StatusText.Foreground = Brushes.Yellow;
            StatusText.Text = "Loading private key...";

            if (!LoadPrivateKeyAndCert(pin, out ICipherParameters privateKey, out X509Certificate certificate))
            {
                StatusText.Foreground = Brushes.Red;
                StatusText.Text = "Failed to load or decrypt private key.";
                return;
            }

            StatusText.Foreground = Brushes.Yellow;
            StatusText.Text = "Signing PDF document...";

            string signedPath = SignPdf(txtFilePath.Text, privateKey, certificate);

            if (!string.IsNullOrEmpty(signedPath))
            {
                StatusText.Foreground = Brushes.Green;
                StatusText.Text = $"PDF signed successfully: {signedPath}";
            }
            else
            {
                StatusText.Foreground = Brushes.Red;
                StatusText.Text = "Failed to sign PDF!";
            }
        }

        /// <summary>
        /// Signs the specified PDF document using the provided private key and X.509 certificate.
        /// The signature is applied using a detached CADES format and saved to a new PDF file.
        /// </summary>
        /// <param name="pdfPath">The full file path of the original unsigned PDF document.</param>
        /// <param name="privateKey">The private key used to sign the document.</param>
        /// <param name="cert">The X.509 certificate corresponding to the private key, used for validation.</param>
        /// <returns>The file path of the newly created, signed PDF document.</returns>
        private string SignPdf(string pdfPath, ICipherParameters privateKey, X509Certificate cert)
        {
            string outputPath = System.IO.Path.Combine(
                System.IO.Path.GetDirectoryName(pdfPath),
                System.IO.Path.GetFileNameWithoutExtension(pdfPath) + "_signed.pdf");

            using (var reader = new PdfReader(pdfPath))
            using (var fs = new FileStream(outputPath, FileMode.Create))
            {
                // Create a PdfStamper to apply the signature
                // Use '\0' to indicate that we want to create a new signature field
                PdfStamper stamper = PdfStamper.CreateSignature(reader, fs, '\0');

                // Set up the signature appearance
                PdfSignatureAppearance appearance = stamper.SignatureAppearance;

                appearance.Reason = "Signed using PDFSignerApp";
                appearance.Location = "Poland";
                appearance.SignDate = DateTime.Now;

                // Create a certificate chain containing a single certificate (the signer’s certificate)
                IList<X509Certificate> chain = new List<X509Certificate> { cert };

                // Create an external signature object using the provided private key and SHA-256 hashing algorithm
                IExternalSignature pks = new PrivateKeySignature(privateKey, "SHA-256");

                // Signs the PDF document using a detached CADES signature.
                // Applies the cryptographic signature to the document appearance using the specified private key,
                // certificate chain, and signature standard (CADES in this case).
                MakeSignature.SignDetached(appearance, pks, chain, null, null, null, 0, CryptoStandard.CADES);
            }

            return outputPath;
        }

        /// <summary>
        /// Attempts to load and decrypt the user's private key from a secured file on the USB drive
        /// using the provided PIN, and generates a corresponding self-signed X.509 certificate.
        /// </summary>
        /// <param name="pin">The PIN used to decrypt the encrypted private key.</param>
        /// <param name="privateKey">Outputs the decrypted private key if successful; otherwise null.</param>
        /// <param name="certificate">Outputs a self-signed X.509 certificate generated from the key; otherwise null.</param>
        /// <returns>
        /// True if the private key was successfully loaded and decrypted, and the certificate generated;
        /// false if an error occurred (e.g., file not found, wrong PIN, decryption failure).
        /// </returns>
        private bool LoadPrivateKeyAndCert(string pin, out ICipherParameters privateKey, out X509Certificate certificate)
        {
            privateKey = null;
            certificate = null;

            try
            {
                // Construct the path to the encrypted private key file on the USB drive
                string keyPath = System.IO.Path.Combine(_currentPendrivePath, "private_key.enc");

                if (!File.Exists(keyPath))
                    return false;

                // Read the encrypted private key data
                byte[] encryptedKey = File.ReadAllBytes(keyPath);

                // Convert the PIN to bytes to use as a decryption key or salt
                byte[] pinBytes = Encoding.UTF8.GetBytes(pin);

                // Decrypt the key using AES
                byte[] decryptedKey = DecryptAES(encryptedKey, pinBytes);

                // Convert the decrypted key to an RSA key object
                using var rsa = RSA.Create();
                rsa.ImportRSAPrivateKey(decryptedKey, out _);

                // Convert the .NET RSA key to BouncyCastle format
                AsymmetricCipherKeyPair keyPair = DotNetUtilities.GetRsaKeyPair(rsa);
                privateKey = keyPair.Private;

                // Generate a self-signed certificate from the private key
                certificate = GenerateSelfSignedCertificate(keyPair);
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        /// <summary>
        /// Decrypts the provided AES-encrypted data using a key derived from the provided PIN and salt.
        /// The encrypted data must contain the IV and salt as the first 32 bytes (16 bytes IV + 16 bytes salt).
        /// </summary>
        /// <param name="encryptedData">The full encrypted byte array, including IV and salt prepended.</param>
        /// <param name="pinBytes">The byte representation of the PIN used for key derivation.</param>
        /// <returns>The decrypted byte array (plaintext).</returns>
        private byte[] DecryptAES(byte[] encryptedData, byte[] pinBytes)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                // Extract the IV from the first 16 bytes
                byte[] iv = new byte[16];
                Array.Copy(encryptedData, 0, iv, 0, 16);
                aes.IV = iv;

                // Extract the salt from the next 16 bytes
                byte[] salt = new byte[16];
                Array.Copy(encryptedData, 16, salt, 0, 16);

                // Concatenate PIN with salt and hash with SHA-256 to derive the AES key
                byte[] pinWithSalt = pinBytes.Concat(salt).ToArray();
                byte[] key;
                using (var sha256 = SHA256.Create())
                {
                    key = sha256.ComputeHash(pinWithSalt);
                }
                aes.Key = key;

                // Extract the actual ciphertext (after IV + salt)
                int encryptedDataStart = 32; // 16 (IV) + 16 (salt)
                byte[] cipherText = new byte[encryptedData.Length - encryptedDataStart];
                Array.Copy(encryptedData, encryptedDataStart, cipherText, 0, cipherText.Length);

                // Perform AES decryption
                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
                }
            }
        }

        /// <summary>
        /// Generates a self-signed X.509 certificate using the provided asymmetric RSA key pair.
        /// The certificate is valid for one year and includes basic subject and issuer information.
        /// </summary>
        /// <param name="keyPair">An RSA key pair used to sign and define the certificate.</param>
        /// <returns>
        /// A self-signed <see cref="X509Certificate"/> object that can be used for PDF signing or other cryptographic purposes.
        /// </returns>
        private X509Certificate GenerateSelfSignedCertificate(AsymmetricCipherKeyPair keyPair)
        {
            // Initialize the certificate generator
            var certGen = new X509V3CertificateGenerator();

            // Define the certificate subject and issuer distinguished name (DN)
            var certName = new X509Name("CN=PDF Signer, O=BSK Project, C=PL");

            // Generate a random 120-bit serial number
            var serialNumber = BigInteger.ProbablePrime(120, new Random());

            certGen.SetSerialNumber(serialNumber);
            certGen.SetIssuerDN(certName); // Issuer = subject for self-signed certificate
            certGen.SetNotBefore(DateTime.UtcNow.AddDays(-1)); // Certificate valid from yesterday
            certGen.SetNotAfter(DateTime.UtcNow.AddYears(1)); // Valid for 1 year
            certGen.SetSubjectDN(certName);
            certGen.SetPublicKey(keyPair.Public); // Use public key from key pair

            // Define the signature algorithm (SHA256 with RSA) and create the certificate
            ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", keyPair.Private);

            return certGen.Generate(signatureFactory);
        }

        /// <summary>
        /// Handles the click event for the "Verify PDF" button.
        /// Loads the stored public key from disk and uses it to verify digital signatures embedded in the selected PDF file.
        /// Displays detailed verification results, including signature validity, signer identity, document integrity,
        /// and whether the signature matches the expected trusted key.
        /// </summary>
        /// <param name="sender">The source of the click event (typically the Verify button).</param>
        /// <param name="e">Event data associated with the click event.</param>
        private void btnVerify_Click(object sender, RoutedEventArgs e)
        {
            string pdfPath = txtFilePath.Text;
            StatusText.Foreground = Brushes.Yellow;
            StatusText.Text = "Loading public key for verification...";

            AsymmetricKeyParameter publicKey = LoadPublicKey();
            if (publicKey == null)
            {
                StatusText.Foreground = Brushes.Red;
                StatusText.Text = "Public key not found! Cannot verify signatures.";
                return;
            }

            StatusText.Foreground = Brushes.Yellow;
            StatusText.Text = "Verifying PDF signatures with public key...";

            try
            {
                var verificationResults = VerifyPdfSignatures(pdfPath, publicKey);

                if (verificationResults.Count == 0)
                {
                    StatusText.Foreground = Brushes.Orange;
                    StatusText.Text = "No signatures found in the PDF.";
                    return;
                }

                var resultText = new StringBuilder();
                resultText.AppendLine($"Found {verificationResults.Count} signature(s):");
                resultText.AppendLine("✓ Verified with trusted public key\n");

                for (int i = 0; i < verificationResults.Count; i++)
                {
                    var result = verificationResults[i];
                    resultText.AppendLine($"Signature {i + 1}:");
                    resultText.AppendLine($"  Valid: {(result.IsValid ? "✅ YES" : "❌ NO")}");
                    resultText.AppendLine($"  Signed with our key: {(result.IsTrustedKeyMatch ? "✅ YES" : "❌ NO")}");
                    resultText.AppendLine($"  Document integrity: {(result.IsDocumentIntegrityValid ? "✅ OK" : "❌ FAILED")}");
                    resultText.AppendLine($"  Certificate valid: {(result.IsCertificateValid ? "✅ OK" : "❌ FAILED")}");
                    resultText.AppendLine($"  Document modified: {(result.IsDocumentModified ? "❌ YES" : "✅ NO")}");
                    resultText.AppendLine($"  Signer: {result.SignerName}");
                    resultText.AppendLine($"  Date: {result.SignDate:yyyy-MM-dd HH:mm:ss}");
                    resultText.AppendLine($"  Reason: {result.Reason}");
                    resultText.AppendLine($"  Location: {result.Location}");

                    if (!string.IsNullOrEmpty(result.ErrorMessage))
                    {
                        resultText.AppendLine($"  ⚠ Issues: {result.ErrorMessage}");
                    }
                    resultText.AppendLine("");
                }

                bool allValid = verificationResults.All(r => r.IsValid);
                bool allTrusted = verificationResults.All(r => r.IsTrustedKeyMatch);

                StatusText.Foreground = allValid && allTrusted ? Brushes.Green : Brushes.Red;

                if (allValid && allTrusted)
                {
                    StatusText.Text = "All signatures are valid and trusted!";
                }
                else if (allValid)
                {
                    StatusText.Text = "Signatures valid but not signed with our key!";
                }
                else
                {
                    StatusText.Text = "Invalid signatures detected!";
                }

                MessageBox.Show(resultText.ToString(), "Signature Verification Results",
                               MessageBoxButton.OK,
                               allValid && allTrusted ? MessageBoxImage.Information : MessageBoxImage.Warning);
            }
            catch (Exception ex)
            {
                StatusText.Foreground = Brushes.Red;
                StatusText.Text = $"Verification failed: {ex.Message}";
                MessageBox.Show($"Error during verification:\n{ex.Message}", "Verification Error",
                               MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Loads the RSA public key from a local file (`public_key.bin`) for signature verification.
        /// Expects the public key to be stored in binary DER format (SubjectPublicKeyInfo).
        /// </summary>
        /// <returns>
        /// An <see cref="AsymmetricKeyParameter"/> representing the loaded public key,
        /// or <c>null</c> if the file doesn't exist or loading fails.
        /// </returns>
        private AsymmetricKeyParameter LoadPublicKey()
        {
            try
            {
                string publicKeyPath = "D:\\public_key.bin";

                if (!File.Exists(publicKeyPath))
                {
                    return null;
                }

                byte[] publicKeyBytes = File.ReadAllBytes(publicKeyPath);

                using var rsa = RSA.Create();
                rsa.ImportRSAPublicKey(publicKeyBytes, out _);

                var rsaParams = rsa.ExportParameters(false);
                var publicKey = DotNetUtilities.GetRsaPublicKey(rsa);

                return publicKey;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Verifies all digital signatures present in a PDF file using a trusted public key.
        /// Checks document integrity, certificate validity, signature origin, and post-signing modifications.
        /// </summary>
        /// <param name="pdfPath">Full path to the PDF file containing signatures.</param>
        /// <param name="trustedPublicKey">The trusted RSA public key for verifying signature origin.</param>
        /// <returns>
        /// A list of <see cref="SignatureVerificationResult"/> containing detailed results for each signature.
        /// </returns>
        private List<SignatureVerificationResult> VerifyPdfSignatures(string pdfPath, AsymmetricKeyParameter trustedPublicKey)
        {
            var results = new List<SignatureVerificationResult>();

            using (var reader = new PdfReader(pdfPath))
            {
                var fields = reader.AcroFields;
                var signatureNames = fields.GetSignatureNames();

                foreach (string signatureName in signatureNames)
                {
                    var result = new SignatureVerificationResult
                    {
                        SignatureName = signatureName
                    };

                    try
                    {
                        var pkcs7 = fields.VerifySignature(signatureName);

                        if (pkcs7 != null)
                        {
                            result.SignerName = pkcs7.SigningCertificate?.SubjectDN?.ToString() ?? "Unknown";
                            result.SignDate = pkcs7.SignDate;
                            result.Reason = pkcs7.Reason ?? "";
                            result.Location = pkcs7.Location ?? "";

                            result.IsDocumentIntegrityValid = pkcs7.Verify();

                            result.IsCertificateValid = VerifyCertificate(pkcs7);

                            result.IsDocumentModified = IsDocumentModifiedAfterSigning(fields, signatureName);

                            result.IsTrustedKeyMatch = VerifyWithTrustedKey(pkcs7, trustedPublicKey);

                            result.IsValid = result.IsDocumentIntegrityValid &&
                                           result.IsCertificateValid &&
                                           !result.IsDocumentModified &&
                                           result.IsTrustedKeyMatch;

                            var errors = new List<string>();
                            if (!result.IsDocumentIntegrityValid)
                                errors.Add("Document integrity check failed");
                            if (!result.IsCertificateValid)
                                errors.Add("Certificate validation failed");
                            if (result.IsDocumentModified)
                                errors.Add("Document was modified after signing");
                            if (!result.IsTrustedKeyMatch)
                                errors.Add("Signature not created with our trusted key");

                            result.ErrorMessage = errors.Count > 0 ? string.Join("; ", errors) : "";
                        }
                        else
                        {
                            result.IsValid = false;
                            result.ErrorMessage = "Could not extract signature data";
                        }
                    }
                    catch (Exception ex)
                    {
                        result.IsValid = false;
                        result.ErrorMessage = ex.Message;
                    }

                    results.Add(result);
                }
            }

            return results;
        }

        /// <summary>
        /// Compares the public key from the signer's certificate with the trusted public key.
        /// Used to verify if the PDF was signed with a known trusted key.
        /// </summary>
        /// <param name="pkcs7">The PKCS#7 signature object from the PDF.</param>
        /// <param name="trustedPublicKey">The trusted public key to compare against.</param>
        /// <returns><c>true</c> if keys match; otherwise, <c>false</c>.</returns>
        private bool VerifyWithTrustedKey(PdfPKCS7 pkcs7, AsymmetricKeyParameter trustedPublicKey)
        {
            try
            {
                var certPublicKey = pkcs7.SigningCertificate?.GetPublicKey();

                if (certPublicKey == null)
                    return false;

                return ArePublicKeysEqual(certPublicKey, trustedPublicKey);
            }
            catch
            {
                return false;
            }
        }
        
        /// <summary>
        /// Compares two RSA public keys by checking their modulus and exponent.
        /// </summary>
        /// <param name="key1">First RSA public key.</param>
        /// <param name="key2">Second RSA public key.</param>
        /// <returns><c>true</c> if both keys have the same modulus and exponent; otherwise, <c>false</c>.</returns>
        private bool ArePublicKeysEqual(AsymmetricKeyParameter key1, AsymmetricKeyParameter key2)
        {
            try
            {
                if (key1 is RsaKeyParameters rsaKey1 && key2 is RsaKeyParameters rsaKey2)
                {
                    return rsaKey1.Modulus.Equals(rsaKey2.Modulus) &&
                           rsaKey1.Exponent.Equals(rsaKey2.Exponent);
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Verifies the validity period and signature of the certificate used in the PDF signature.
        /// </summary>
        /// <param name="pkcs7">The PKCS#7 signature object.</param>
        /// <returns><c>true</c> if the certificate is valid and not expired; otherwise, <c>false</c>.</returns>
        private bool VerifyCertificate(PdfPKCS7 pkcs7)
        {
            try
            {
                var cert = pkcs7.SigningCertificate;
                if (cert == null)
                    return false;

                var now = DateTime.Now;
                if (now < cert.NotBefore || now > cert.NotAfter)
                    return false;

                return pkcs7.Verify();
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Checks whether the document was modified after the signature was applied.
        /// </summary>
        /// <param name="fields">The AcroFields object containing signature information.</param>
        /// <param name="signatureName">The name/identifier of the signature field.</param>
        /// <returns><c>true</c> if the document was modified after signing; otherwise, <c>false</c>.</returns>
        private bool IsDocumentModifiedAfterSigning(AcroFields fields, string signatureName)
        {
            try
            {
                return !fields.SignatureCoversWholeDocument(signatureName);
            }
            catch
            {
                return true;
            }
        }

        /// <summary>
        /// Represents the detailed result of verifying a single digital signature in a PDF document.
        /// </summary>
        public class SignatureVerificationResult
        {
            /// <summary>
            /// Gets or sets the name/identifier of the signature field in the PDF.
            /// </summary>
            public string SignatureName { get; set; }

            /// <summary>
            /// Gets or sets the signer’s name as extracted from the signing certificate.
            /// </summary>
            public string SignerName { get; set; }

            /// <summary>
            /// Gets or sets the date and time when the document was signed.
            /// </summary>
            public DateTime SignDate { get; set; }

            /// <summary>
            /// Gets or sets the reason provided for the signature, if available.
            /// </summary>
            public string Reason { get; set; }

            /// <summary>
            /// Gets or sets the location where the document was signed, if specified.
            /// </summary>
            public string Location { get; set; }

            /// <summary>
            /// Gets or sets a value indicating whether the signature is valid overall.
            /// This typically means all checks passed (integrity, certificate, trusted key, etc.).
            /// </summary>
            public bool IsValid { get; set; }

            /// <summary>
            /// Gets or sets a value indicating whether the document’s integrity is intact
            /// (i.e., the document was not altered after signing).
            /// </summary>
            public bool IsDocumentIntegrityValid { get; set; }

            /// <summary>
            /// Gets or sets a value indicating whether the signing certificate is valid and not expired.
            /// </summary>
            public bool IsCertificateValid { get; set; }

            /// <summary>
            /// Gets or sets a value indicating whether the document has been modified after signing.
            /// </summary>
            public bool IsDocumentModified { get; set; }

            /// <summary>
            /// Gets or sets a value indicating whether the signature was created using the trusted public key.
            /// </summary>
            public bool IsTrustedKeyMatch { get; set; } = false;

            /// <summary>
            /// Gets or sets any error messages or warnings encountered during verification.
            /// </summary>
            public string ErrorMessage { get; set; }
        }
    }
}
