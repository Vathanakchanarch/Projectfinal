# import os
# from core.Quanratine import Quanrantine
# import zipfile

# class RemoveVirus(Quanrantine):
#     def __init__(self):
#         super().__init__(None)
#         self.New_zip = self.toQuanrantine + ".tmp"

#     def Remove(self):
#         with zipfile.ZipFile(self.toQuanrantine, 'r') as z:
#             listfile = z.namelist()
#             if len(listfile) < 1:
#                 print("Don't have Virus!")
#                 return 1
#             files = [n.strip() for n in listfile]
#         print("Files virus:")
#         for i in files:
#             print(i)
#         print("1.Remove specific file:")
#         print("2.Remove all:")
#         option=input("Enter your option:")

#         if option=="1":
#             index = int(input("Enter the number of the file to delete: "))
#             delete_file = files[index]
#             with zipfile.ZipFile(self.toQuanrantine, 'r') as z_in:
#                 with zipfile.ZipFile(self.New_zip, 'w') as z_out:
#                     for i in files:
#                         if i != delete_file:
#                             z_out.writestr(i, z_in.read(i))
#             os.remove(self.toQuanrantine)
#             os.rename(self.New_zip, self.toQuanrantine)
#             print(f"Removed: {delete_file}")
#         elif option == '2':
#             with zipfile.ZipFile(self.toQuanrantine, 'w') as z:
#                 z.writestr("","")
#             print("All files removed!")
#         else:
#             print("Invalid option!")



import os
from core.Quanratine import Quanrantine
import zipfile

class RemoveVirus(Quanratine):
    def __init__(self):
        # Calls parent constructor, which initializes self.toQuanrantine and self.password
        super().__init__(None) 
        self.New_zip = self.toQuanrantine + ".tmp"

    def Remove(self):
        # --- Authentication Check ---
        input_password = input("Enter the Quarantine ZIP password for authentication: ").encode()
        
        if input_password != self.password:
            print("Authentication failed! Incorrect password.")
            return 0
        # --------------------------

        try:
            with zipfile.ZipFile(self.toQuanrantine, 'r') as z:
                # Get list of files. This works even with encrypted files.
                listfile = z.namelist()
                
                if len(listfile) < 1:
                    print("Don't have any quarantined files!")
                    return 1
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


        print("Files virus:")
        for index, i in enumerate(files):
            print(f"{index + 1}. {i}") 
            
        print("1. Remove specific file:")
        print("2. Remove all:")
        option = input("Enter your option: ")

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
                                    
                    os.remove(self.toQuanrantine)
                    os.rename(self.New_zip, self.toQuanrantine)
                    print(f"Successfully removed: {delete_file}")
                else:
                    print("Invalid file number!")
            except ValueError:
                print("Invalid input. Please enter a number.")
            except Exception as e:
                print(f"Error during file removal: {e}")
                
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