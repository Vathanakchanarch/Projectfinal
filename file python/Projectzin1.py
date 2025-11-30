import os
import hashlib
import shutil
class MalwareDetection:
    def __init__(self, path):
        self.path = path
        self.virus_hash_file = r"D:\Y2\T1\PYTHON FOR CYBER\project\fileVirus\virusHash.txt"
        self.virus_info_file = r"D:\Y2\T1\PYTHON FOR CYBER\project\fileVirus\virusinfo.txt"

        
        self.maleware = []
        self.file_count = 0



    def _virus_database(self):
        with open(self.virus_hash_file, "r") as v_hash:
            hashes = [ line.strip() for line in v_hash.readlines()]
        with open(self.virus_info_file, "r") as v_info:
            info = [line.strip() for line in v_info.readlines()]
        return hashes, info

    def get_fileHash(self, file_path):
        with open(file_path, "rb") as f:
            file = f.read()
            Hash256 = hashlib.sha256(file).hexdigest()
        return Hash256

    def check_filevirus(self, file_path):
        virus_hashes,virus_info=self._virus_database()
        file_hash = self.get_fileHash(file_path)
        if file_hash in virus_hashes:
            index = virus_hashes.index(file_hash)
            return virus_info[index]
        return None

    def check_folder(self, path=None):
        if path is None:
            path = self.path
        if os.path.isfile(path):
            self.file_count += 1
            maleware = self.check_filevirus(path)
            if maleware:
                self.malware.append({"path":path,"Maleware":maleware})
            return self.maleware
        for i in os.listdir(path):
            JoinFile = os.path.join(path, i)

            if os.path.isfile(JoinFile):
                self.file_count += 1
                maleware = self.check_filevirus(JoinFile)
                if maleware:
                    self.maleware.append({"path": JoinFile,"Maleware": maleware})

            elif os.path.isdir(JoinFile):
                self.check_folder(JoinFile)

        return self.maleware

    def count(self):
        return self.file_count

class RemoveVirus(MalwareDetection):
    def __init__(self, malware_list):
        self.malware_list = malware_list

    def remove(self):
        for filepath, virusname in self.malware_list:
            try:
                os.remove(filepath)
                print("Successful Removed: {0} ({1})".format(filepath,virusname))
            except Exception as e:
                print("! Failed to remove {0}: {1}".format(filepath,e))


class scanner():
    def __init__ (self,path):
        self.path=path
        self.total=0
        self.scan_file=0
        self.detetor=MalwareDetection(path)
        self.Maleware=0
        self.ListMaleware=[]
    
    def scan(self):


        self.ListMaleware=self.detetor.check_folder()
        self.total=self.detetor.count()

        print("Total file :{}".format(self.total))

        print("file Virus:{}".format(self.ListMaleware))

        for i in self.ListMaleware:
            self.Maleware+=1

        print("File Scan: {}\nFile Virus:{}".format(self.total,self.Maleware))

    
class Quanrantine(MalwareDetection):
    def __init__(self):
        super().__init__(None)
        self.toQuanrantine=r"D:\Y2\T1\PYTHON FOR CYBER\project\Quanrantine"
    def Movefile(self,file_path):
        Malware=self.check_folder(file_path)
        for i in Malware:
            for key,value in i.items():
                try:
                    if key=="path":
                        file=value
                        shutil.copy2(file,self.toQuanrantine)
                        os.remove(file)
                    else: 
                        VirusName=value
                        print("Move virus Name:{} TO Folder Quantine".format(VirusName))
                except Exception as e:
                    print("Error Cannot move {0}".format(e))

while(True):
    print("Please Choose Your options: ")
    print("1.Scan file:")
    print("2.Quarine:")
    print("3.Remove Virus:")
    print("4.Exit")
    Options=int(input("Enter your Options:"))
    
    if Options==1:
        print("Welcome To Scan file:")
        file=input("Enter file here:")
        S=scanner(file)
        S.scan()
        break
    