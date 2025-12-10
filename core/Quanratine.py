import os
import zipfile
from core.setting import MalwareDetection
class Quanrantine(MalwareDetection):
    def __init__(self,path,password='12345'):
        super().__init__(path)
        self.toQuanrantine=r"C:\Users\U-ser\Projectfinal\Quarantine.zip"
        self.password=password.encode()
    def Movefile(self):
        Malware=self.check_folder(self.path)
        for i in Malware:
            for key,value in i.items():
                file=value
                try:
                    if key=='path':
                        with zipfile.ZipFile(self.toQuanrantine,'a') as zipp:
                            zipp.write(file,arcname=os.path.basename(file))
                            zipp.setpassword(self.password)
                        os.remove(file)
                        print("Move Secussfully:{}".format(os.path.basename(file)))
                except Exception as e:
                    print ("Error cannot move {}".format(e))

