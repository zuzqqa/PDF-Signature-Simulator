using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Microsoft.Win32;

namespace PDFSignerApp
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void btnSelectFile_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Filter = "PDF Files (*.pdf)|*.pdf", 
                Title = "Select PDF File"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                string selectedFile = openFileDialog.FileName;
                txtFilePath.Text = selectedFile;
                statusMessage.Text = "PDF file selected!";
            }
            else
            {
                statusMessage.Text = "No file selected.";
            }
        }

        private void btnVerify_Click(object sender, RoutedEventArgs e)
        {

        }

        private void btnSign_Click(object sender, RoutedEventArgs e)
        {

        }
    }
}