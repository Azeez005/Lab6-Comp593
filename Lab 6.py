import os
import requests
import hashlib
import subprocess

def main():
    # Get the expected SHA-256 hash value of the VLC installer
    expected_sha256 = get_expected_sha256()

    # Download (but don't save) the VLC installer from the VLC website
    installer_data = download_installer()

    # Verify the integrity of the downloaded VLC installer by comparing the
    # expected and computed SHA-256 hash values
    if installer_ok(installer_data, expected_sha256):
        # Save the downloaded VLC installer to disk
        installer_path = save_installer(installer_data)

        # Silently run the VLC installer
        run_installer(installer_path)

        # Delete the VLC installer from disk
        delete_installer(installer_path)

def get_expected_sha256():
    """Downloads the text file containing the expected SHA-256 value for the VLC installer file from the 
    videolan.org website and extracts the expected SHA-256 value from it.

    Returns:
        str: Expected SHA-256 hash value of VLC installer
    """
    url = "http://download.videolan.org/pub/videolan/vlc/last/win64/SHA256SUMS"
    response = requests.get(url)
    if response.status_code == 200:
        # Extract the expected SHA-256 hash value for the installer
        sha256_lines = response.text.split('\n')
        for line in sha256_lines:
            if line.endswith('.exe'):
                expected_sha256 = line.split()[0]
                return expected_sha256
    return None

def download_installer():
    """Downloads, but does not save, the .exe VLC installer file for 64-bit Windows.

    Returns:
        bytes: VLC installer file binary data
    """
    url = "http://download.videolan.org/pub/videolan/vlc/last/win64/vlc-3.0.20-win64.exe"
    response = requests.get(url)
    if response.status_code == 200:
        return response.content
    return None

def installer_ok(installer_data, expected_sha256):
    """Verifies the integrity of the downloaded VLC installer file by calculating its SHA-256 hash value 
    and comparing it against the expected SHA-256 hash value. 

    Args:
        installer_data (bytes): VLC installer file binary data
        expected_sha256 (str): Expeced SHA-256 of the VLC installer

    Returns:
        bool: True if SHA-256 of VLC installer matches expected SHA-256. False if not.
    """    
    if installer_data and expected_sha256:
        sha256_hash = hashlib.sha256()
        sha256_hash.update(installer_data)
        calculated_sha256 = sha256_hash.hexdigest()
        return calculated_sha256 == expected_sha256
    return False

def save_installer(installer_data):
    """Saves the VLC installer to a local directory.

    Args:
        installer_data (bytes): VLC installer file binary data

    Returns:
        str: Full path of the saved VLC installer file
    """
    if installer_data:
        temp_folder = os.getenv('TEMP')
        installer_path = os.path.join(temp_folder, "vlc_installer.exe")
        with open(installer_path, 'wb') as installer_file:
            installer_file.write(installer_data)
        return installer_path
    return None

def run_installer(installer_path):
    """Silently runs the VLC installer.

    Args:
        installer_path (str): Full path of the VLC installer file
    """    
    if installer_path:
        subprocess.run([installer_path, '/S'])

def delete_installer(installer_path):
    """Deletes the VLC installer file.

    Args:
        installer_path (str): Full path of the VLC installer file
    """
    if installer_path:
        os.remove(installer_path)

if __name__ == '__main__':
    main()

