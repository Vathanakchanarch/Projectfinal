import os
import hashlib
from colorama import Fore,init
import pyfiglet

class MalwareDetection:
    def __init__(self, path):
        # Path to scan (file or directory)
        self.path = path
        # Database files containing malware hashes and names
        self.virus_hash_file = r"D:\University\Y2\T1\PYTHON FOR CYBER\project\database\virusHash.txt"
        self.virus_info_file = r"D:\University\Y2\T1\PYTHON FOR CYBER\project\database\virusInfo.txt"
        # List to store detected malware information
        self.maleware = []
        # Counter for total scanned files
        self.file_count = 0
        

    # Read all saved malware SHA-256 hashes and malware imformation and store as list
    # Return both lists to check files against known malware
    def __virus_database(self):
        with open(self.virus_hash_file, "r") as v_hash:
            hashes = [ line.strip() for line in v_hash.readlines()]
        with open(self.virus_info_file, "r") as v_info:
            info = [line.strip() for line in v_info.readlines()]
        return hashes, info


   

    def get_fileHash(self, file_path):
        try:
            # - Open file in binary mode
            with open(file_path, "rb") as f:
                # - Read file 
                file = f.read()
                #Calculate SHA-256 hash from binary to hex
                Hash256 = hashlib.sha256(file).hexdigest()
             # - Return the hash value
            return Hash256
         # If file cannot be read, show error and skip file
        except Exception as e:
            print(Fore.RED + f"Cannot read file {file_path}: {e}")
            return None


    # STEP 4: Check if the file hash matches a known virus hash
    # - Get virus database
    # - Generate hash of the current file
    # - Compare file hash with malware hash list
    # - Return malware name if found


    def check_filevirus(self, file_path):
         # - Get virus database and virus_hashes ,virus_info are list 
        virus_hashes,virus_info=self.__virus_database()
        #  Generate hash of the current file that we want to scan
        file_hash = self.get_fileHash(file_path)
        #  Compare file hash with malware hash list
        if file_hash in virus_hashes:
            # find index malware in virus_hashes
            index = virus_hashes.index(file_hash)
            # return as index from virus_info
            return virus_info[index]
        # if file not virus return false or None
        return None



    # STEP 5: Scan files and folders recursively
    # - If path does not exist, record error
    # - If path is a file, scan it
    # - If path is a folder, scan all files and subfolders

    def check_folder(self, path=None):
        # Use initial path if no new path is provided
        if path is None:
            path = self.path
        # Check if path exists
        if not os.path.exists(path):
            print(Fore.RED + f"[Error] Path does not exist: {path}")
            return self.maleware

        try:
        # If the path is a single file
            if os.path.isfile(path):
                self.file_count += 1
                maleware = self.check_filevirus(path)
        # If malware is detected, save its details
                if maleware:
                    self.maleware.append({"path":path,"Maleware":maleware})
                return self.maleware
        except Exception as e:
            print("Error {}".format(e))
         # If the path is a directory, list all contents
        ListFileFolder=os.listdir(path)
        for i in ListFileFolder:
            JoinFile = os.path.join(path, i)
        # If item is a file, scan it
            if os.path.isfile(JoinFile):
                self.file_count += 1
                maleware = self.check_filevirus(JoinFile)
                if maleware:
                    self.maleware.append({"path": JoinFile,"Maleware": maleware})
        # If item is a folder, scan it recursively
            else:
                self.check_folder(JoinFile)

        return self.maleware
     # STEP 6: Return total number of scanned files
    def count(self):
        return self.file_count

# STEP 7: Initialize colorama for colored console output
init(autoreset=True)
# STEP 8: Display application banner
# - Show program name using ASCII art
# - Add colored welcome message
def display_banner():
    print(Fore.GREEN + "============================================================================================")
    print(Fore.BLUE + pyfiglet.figlet_format("             Threat Hunter"))
    print(Fore.GREEN + "============================================================================================")
    print(Fore.GREEN + "                           Welcome To My Application")
    print(Fore.GREEN + "============================================================================================")
