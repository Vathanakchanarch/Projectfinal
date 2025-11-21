import os
import hashlib
import magic
import pyfiglet
import requests

class MaleDectection:
    MaleWareName=[]
    fileCount=0

    def __init__(self,path):
        self.path=path
        self.__FileVirusHashes=r"D:\Y2\T1\PYTHON FOR CYBER\project\fileVirus\virusHash.txt"
        self.__FileVirusInfo=r"D:\Y2\T1\PYTHON FOR CYBER\project\fileVirus\virusinfo.txt"
    def get_fileHash(self,file_path):
        with open(file_path,"rb") as f:
            file=f.read()
            Hash256=hashlib.sha256(file).hexdigest()
        return Hash256


    def check_fileVirus(self,file_path):
        FileHash=self.get_fileHash(file_path)
        with open(self.__FileVirusHashes,"r") as v_hash:
            virus_hashes=[line.strip() for line in v_hash.readlines()]
        with open(self.__FileVirusInfo,"r") as v_info:
            virus_info=[line.strip() for line in v_info.readlines()]
        if FileHash in virus_hashes:
            index=virus_hashes.index(FileHash)
            return virus_info[index]
        return 0


    def check_folder(self):
        if os.path.isdir(self.path):
            dir_list=os.listdir(self.path)
            for i in dir_list:
                File=os.path.join(self.path,i)
                MaleWare=None
                if os.path.isfile(File):
                    MaleDectection.fileCount+=1
                    MaleWare=self.check_fileVirus(File)
                if os.path.isdir(File):
                    old_path = self.path
                    self.path = File
                    self.check_folder()
                    self.path = old_path

                if MaleWare:
                    MaleDectection.MaleWareName.append((File,MaleWare ))
            return MaleDectection.MaleWareName
        else:
            return self.check_fileVirus(self.path)
    def Count(self):
        return MaleDectection.fileCount

class RemoveVirus(MaleDectection):
    def remove(self):
        for filepath, virusname in MaleDectection.MaleWareName:
            try:
                os.remove(filepath)
                print(f"Removed: {filepath} ({virusname})")
            except Exception as e:
                print(f"Failed to remove {filepath}: {e}")





c1=RemoveVirus(r"D:\Y2\T1\PYTHON FOR CYBER\project\button")
# get=c1.check_fileVirus(r"D:\Y2\T1\PYTHON FOR CYBER\project\fileVirus\screen.jpg")
c1.check_folder()
get=c1.Count()
print(get)