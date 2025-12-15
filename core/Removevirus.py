import os
from core.Quanratine import Quanrantine
import zipfile
from colorama import Fore,init
import pyfiglet
class RemoveVirus(Quanrantine):
    def __init__(self):
        # - Inherit from Quanrantine class
        # - Call parent constructor to get quarantine ZIP path and password
         # - Create a temporary ZIP file name for safe modification
        super().__init__(None) 
        self.New_zip = self.toQuanrantine + ".tmp"  # Temporary ZIP file




    # - Authenticate user with ZIP password
    # - Display quarantined files
    # - Allow user to remove one file or all files
    def Remove(self):
        # --- Authentication Check ---
        input_password = input("Enter the Quarantine ZIP password for authentication: ").encode()
        # Password authentication
        if input_password != self.password:
            print("Authentication failed! Incorrect password.")
            return 0
        # --------------------------

        try:
            # Open quarantine ZIP and list stored files
            with zipfile.ZipFile(self.toQuanrantine, 'r') as z:
                 # Get all file names inside the ZIP.
                listfile = z.namelist()
                # Check if quarantine is empty
                if len(listfile) < 1:
                    print("Don't have any quarantined files!")
                    return 1
                 # file name list
                files = [n.strip() for n in listfile]
            
        except FileNotFoundError:
            print(f"Error: Quarantine file not found at {self.toQuanrantine}")
            return 0
        except zipfile.BadZipFile:
             print("Error: The file is not a valid zip file.")
             return 0
        except Exception as e:
            print(f"An unexpected error occurred during file access: {e}")
            return 0

        # Display quarantined virus files
        print("Files virus:")
        for index, i in enumerate(files):
            print(Fore.RED + "{0}. {1}".format(index+1,i)) 
        # Show removal options   
        print(Fore.GREEN + "     1. Remove specific file:")
        print(Fore.GREEN + "     2. Remove all:")
        option = input("Enter your option: ")
        # Remove a specific file from quarantine
        if option == "1":
            try:
                # Get file number from user
                index_input = input("Enter the **number** of the file to delete (e.g., 1): ")
                index = int(index_input) - 1
                
                if 0 <= index < len(files):
                    delete_file = files[index]
                    
                    # Process the zip file to remove the specific file
                    with zipfile.ZipFile(self.toQuanrantine, 'r') as z_in:
                        with zipfile.ZipFile(self.New_zip, 'w') as z_out:
                            for i in files:
                                if i != delete_file:
                                    # Use the stored password to read the encrypted content
                                    file_content = z_in.read(i, pwd=self.password)
                                    z_out.writestr(i, file_content)
                     # Replace old ZIP with new ZIP                
                    os.remove(self.toQuanrantine)
                    os.rename(self.New_zip, self.toQuanrantine)
                    print(f"Successfully removed: {delete_file}")
                else:
                    print("Invalid file number!")
            except ValueError:
                print("Invalid input. Please enter a number.")
            except Exception as e:
                print(f"Error during file removal: {e}")
         # Remove all quarantined files       
        elif option == '2':
            # Remove all files by overwriting the zip with an empty one
            try:
                with zipfile.ZipFile(self.toQuanrantine, 'w') as z:
                    pass
                if os.path.exists(self.New_zip):
                    os.remove(self.New_zip) # Cleanup temporary file
                print("All files removed! The Quarantine ZIP is now empty.")
            except Exception as e:
                print(f"Error during complete removal: {e}")
                
        else:
            print("Invalid option!")