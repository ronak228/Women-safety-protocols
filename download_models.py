import gdown
import os
from tqdm import tqdm

def download_file(url, output_path):
    try:
        gdown.download(url, output_path, quiet=False)
        print(f"Successfully downloaded {os.path.basename(output_path)}")
    except Exception as e:
        print(f"Error downloading {os.path.basename(output_path)}: {str(e)}")
        return False
    return True

def main():
    # Create models directory if it doesn't exist
    if not os.path.exists('models'):
        os.makedirs('models')

    # Model files and their corresponding URLs
    model_files = {}  # No models needed

    success = True
    for filename, url in model_files.items():
        output_path = os.path.join('models', filename)
        if not os.path.exists(output_path):
            print(f"\nDownloading {filename}...")
            if not download_file(url, output_path):
                success = False
                break
        else:
            print(f"{filename} already exists, skipping download.")

    if success:
        print("\nAll model files downloaded successfully!")
        print("You can now run the application with the analytics features.")
    else:
        print("\nError: Some model files could not be downloaded.")
        print("Please check your internet connection and try again.")

if __name__ == "__main__":
    main() 