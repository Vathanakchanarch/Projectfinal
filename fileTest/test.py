import os
import hashlib
import magic
import pyfiglet
import requests

#setting for for checking virus
class MaleDectection:
    MaleWareName=[]
    fileCount=0

    def __init__(self,path):
        self.path=path
        self.__FileVirusHashes=r"D:\Y2\T1\PYTHON FOR CYBER\project\fileVirus\virusHash.txt"
        self.__FileVirusInfo=r"D:\Y2\T1\PYTHON FOR CYBER\project\fileVirus\virusinfo.txt"

#getting hash from file 
    def get_fileHash(self,file_path):
        with open(file_path,"rb") as f:
            file=f.read()
            Hash256=hashlib.sha256(file).hexdigest()
        return Hash256

#Checking and comparing file hash that we want to scannig with file hash virus and getting index of file that is virus in virusinfo database 
    def check_fileVirus(self,file_path):
        FileHash=self.get_fileHash(file_path)
        with open(self.__FileVirusHashes,"r") as v_hash:
            virus_hashes=[line.strip() for line in v_hash.readlines()]
        with open(self.__FileVirusInfo,"r") as v_info:
            virus_info=[line.strip() for line in v_info.readlines()]
        if FileHash in virus_hashes:
            index=virus_hashes.index(FileHash)
            return virus_info[index]
        return None

#Checking folder 
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

C1=MaleDectection(r"D:\Y2\T1\PYTHON FOR CYBER\project\fileVirus\screen.jpg")
g=C1.check_folder()

print(g)


# class SimpleScanner:
    
#     def __init__(self, path):
#         self.path = path
#         self.detector = MaleDectection(path)
#         self.total_files = 0
#         self.scanned = 0
#         self.infected_count = 0

#     def scan(self):
#         try:
#             # STEP 1: Run the malware detector to count files
#             self.detector.check_folder()

#             # STEP 2: Get file count from MaleDectection
#             self.total_files = self.detector.Count()
#             print(f"start: {self.total_files}")

#             # STEP 3: Prepare file list
#             if os.path.isfile(self.path):
#                 files_iter = [self.path]
#             else:
#                 files_iter = (os.path.join(root, f) 
#                               for root, _, files in os.walk(self.path)
#                               for f in files)

#             # STEP 4: Scan files
#             for file_path in files_iter:
#                 self.scanned += 1
#                 try:
#                     malware = self.detector.check_fileVirus(file_path)
#                 except Exception as e:
#                     print(f"error: Failed to read {file_path}: {e}")
#                     print(f"progress: {self.scanned}")
#                     continue

#                 print(f"progress: {self.scanned}")
#                 if malware:
#                     self.infected_count += 1
#                     print(f"infected: {file_path}, {malware}")

#             print(f"Scan file: {self.scanned}, file virus: {self.infected_count}")

#         except Exception as e:
#             print(f"error: {e}")
#             print("done: 0, 0")
# # # Example usage:
# # scanner = SimpleScanner(r"D:\Y2\T1\PYTHON FOR CYBER\project\scan_folder")
# # scanner.scan()


# # C1 = MalwareDetection(r"D:\Y2\T1\PYTHON FOR CYBER\project\fileVirus")
# # results = C1.check_folder()

# # print("Detected Malware:")
# # print(results)

# # print("Files Scanned:", C1.count())
# # # Path to scan
scan_path = r"D:\Y2\T1\PYTHON FOR CYBER\project\fileVirus"

# Create the scanner object
scanner = SimpleScanner(scan_path)

# Start scanning
scanner.scan()
# B=C.get_fileHash(r"D:\Y2\T1\PYTHON FOR CYBER\project\fileTest\keylogger.zip")
# z=C.check_filevirus(r"D:\Y2\T1\PYTHON FOR CYBER\project\fileTest\keylogger.zip")
# print(z)

# G=scanner(r"D:\Y2\T1\PYTHON FOR CYBER\project\fileTest\keylogger.zip")
# M=G.scan()
# print(M)

# W=Quanrantine(r"D:\Y2\T1\PYTHON FOR CYBER\project\TestQuanratin")
# W.Movefile(r"D:\Y2\T1\PYTHON FOR CYBER\project\TestQuanratin")
