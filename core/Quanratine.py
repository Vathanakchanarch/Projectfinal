import os
import zipfile
from core.setting import MalwareDetection
class Quanrantine(MalwareDetection):
    # - Inherit all scanning features from MalwareDetection
    # - Set the quarantine ZIP file location
    # - Set a password for the ZIP file
    def __init__(self,path,password='12345'):
        # Initialize parent class
        super().__init__(path)
        self.toQuanrantine=r"D:\University\Y2\T1\PYTHON FOR CYBER\project\Quarantine.zip"
        # Encode password for ZIP
        self.password=password.encode()



    # - Scan the given path for malware
    # - For each detected malware file:
    #   • Add it to the quarantine ZIP
    #   • Protect the ZIP with a password
    #   • Remove the original infected file from the system
    def Movefile(self):
         # Scan folder and get list of detected malware
        Malware=self.check_folder(self.path)
         # Loop through each detected malware entry
        for i in Malware:
            for key,value in i.items():
                file=value
                try:
                    # Only process file paths
                    if key=='path':
                        # Open quarantine ZIP file in append mode
                        with zipfile.ZipFile(self.toQuanrantine,'a') as zipp:
                             # Add infected file to ZIP (store only file name)
                            zipp.write(file,arcname=os.path.basename(file))
                            # Set password for ZIP file
                            zipp.setpassword(self.password)
                        # Remove the original infected file after quarantine
                        os.remove(file)
                        print("Move Secussfully:{}".format(os.path.basename(file)))
                except Exception as e:
                    print ("Error cannot move {}".format(e))

