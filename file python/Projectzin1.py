import os
import hashlib
import shutil

class MalwareDetection:
    def __init__(self, path):
        self.path = path
        self.virus_hash_file = r"D:\Y2\T1\PYTHON FOR CYBER\project\DatabaseVirus\virusHash.txt"
        self.virus_info_file = r"D:\Y2\T1\PYTHON FOR CYBER\project\DatabaseVirus\virusinfo.txt"
        self.maleware = []
        self.file_count = 0


    def __virus_database(self):
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
        virus_hashes,virus_info=self.__virus_database()
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
                self.maleware.append({"path":path,"Maleware":maleware})
            return self.maleware
        ListFileFolder=os.listdir(path)
        for i in ListFileFolder:
            JoinFile = os.path.join(path, i)

            if os.path.isfile(JoinFile):
                self.file_count += 1
                maleware = self.check_filevirus(JoinFile)
                if maleware:
                    self.maleware.append({"path": JoinFile,"Maleware": maleware})

            else:
                self.check_folder(JoinFile)

        return self.maleware

    def count(self):
        return self.file_count

class scanner(MalwareDetection):
    def __init__ (self,path):
        super().__init__(path)
        self.path=path
        self.TotalFile=0
        self.scan_file=0
        self.Maleware=0
        self.ListMaleware=[]
    def scan(self):
        self.ListMaleware=self.check_folder(self.path)
        self.TotalFile=self.count()
        print("Total file :{}".format(self.TotalFile))
        print("file Virus:{}".format(self.ListMaleware))
        for i in self.ListMaleware:
            self.Maleware+=1
        print("File Scan: {}\nFile Virus:{}".format(self.TotalFile,self.Maleware))

    
class Quanrantine(MalwareDetection):
    def __init__(self,path):
        super().__init__(path)
        self.toQuanrantine=r"D:\Y2\T1\PYTHON FOR CYBER\project\Quanrantine"
    def Movefile(self):
        Malware=self.check_folder(self.path)
        for i in Malware:
            for key,value in i.items():
                try:
                    if key=="path":
                        file=value
                        shutil.copy2(file,self.toQuanrantine)
                        os.remove(file)
                    else: 
                        VirusName=value
                        print("Move virus Name:{} TO Folder Quanrantine".format(VirusName))
                except Exception as e:
                    print("Error Cannot move {0}".format(e))


class RemoveVirus(Quanrantine):
    def __init__(self):
        super().__init__(None)
    def Remove(self):
        for i in  os.listdir(self.toQuanrantine):
            JoinFile=os.path.join(self.toQuanrantine,i)
            try:
                if os.path.exists(JoinFile):
                    os.remove(JoinFile)
                else:
                    print("File Quanratine Don't have Virus!")
            except Exception as e:
                print("file error: {0}".format(e))
            else:
                print("Remove virus sucessfully:")
            finally:
                print("Complete.")

C=MalwareDetection(r"D:\Y2\T1\PYTHON FOR CYBER\project\fileTest\keylogger.zip")

while(True):
    print("Please Choose Your options: ")
    print("1.Scan file:")
    print("2.Quarantine:")
    print("3.Remove Virus:")
    print("4.Exit")
    Options=input("Enter your Options:")
    
    if Options=="1":
        print("Welcome To Scan file:")
        file=input("Enter file here:")
        S=scanner(file)
        S.scan()
        choice=input("Do you want to contiue[y/n]?")
        if choice=='y'or choice=='Y':
            continue
        elif choice=='N' or choice=='n':
            break
        
    if Options == "2":
        print("Quanrantine file :")
        file=input("Enter your File:")
        Q=Quanrantine(file)
        Q.Movefile()
        choice=input("Do you want to contiue[y/n]?")
        if choice=='y'or choice=='Y':
            continue
        elif choice=='N' or choice=='n':
            break
    if Options == "3" :
        print ("Remove Virus From Quanrantine:")
        R=RemoveVirus()
        R.Remove()
        choice=input("Do you want to contiue[y/n]?")
        if choice=='y'or choice=='Y':
            continue
        elif choice=='N' or choice=='n':
            break

    if Options == "4" :
        print("Exit Successfully.Thank you!")
        break
    
    else:
        print("wrong Options . Please Try again! ")