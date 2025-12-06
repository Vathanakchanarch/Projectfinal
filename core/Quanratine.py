import os
import shutil
import zipfile
from core.setting import MalwareDetection

class Quanrantine(MalwareDetection):
    def __init__(self,path):
        super().__init__(path)
        self.toQuanrantine=r"D:\Y2\T1\PYTHON FOR CYBER\Projectstruct\Quarantine.zip"
    def Movefile(self):
        Malware=self.check_folder(self.path)
        for i in Malware:
            for key,value in i.items():
                file=value
                try:
                    if key=='path':
                        with zipfile.ZipFile(self.toQuanrantine,'a') as zipp:
                            zipp.write(file,arcname=os.path.basename(file))
                        os.remove(file)
                        print("Move Secussfully:{}".format(os.path.basename(file)))
                except Exception as e:
                    print ("Ërror cannot move {}".format(e))

