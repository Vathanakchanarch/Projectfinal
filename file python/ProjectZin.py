import os
import hashlib
import magic
import pyfiglet
import requests

MalewareName = []

#get hashes from file
def get_hash(file_path):
    with open(file_path, "rb") as f:
        file = f.read()
        hash_sh256 = hashlib.sha256(file).hexdigest()
    return hash_sh256

def check_malware(filePath):
    #get file hashes that we want to scan
    hashOfFile = get_hash(filePath)
    
    # Read virus hashes
    with open("virus.txt", 'r') as fileVirus:
        virus_hashes = [line.strip() for line in fileVirus.readlines()]
    
    # Read virus info
    with open("virusinfo.txt", 'r') as f_info:
        virus_info = [line.strip() for line in f_info.readlines()]
    
    if hashOfFile in virus_hashes:
        h = virus_hashes.index(hashOfFile)
        return virus_info[h]  # return malware name
    else:
        return 0

def check_folder(path):
    dirs_list = os.listdir(path)
    file=""
    for i in dirs_list:
        file= path + "\\" + i
        malware = check_malware(file)
        if malware:  # if malware found
            MalewareName.append(file)
            print("Malware found: {0} in {1}".format(malware,file))

def removeMaleware(path):
    check_folder(path)
    for i in MalewareName:
        try:
            os.remove(i)
            print("Removed malware file: {}".format(i))
        except Exception as e :
            print("Error removing {0}: {1}".format(i,e))
            
def count_file_scan(path):
    count=0
    dir_list=os.listdir(path)
    for i in dir_list:
        i_path=os.path.join(path,i)
        if os.path.isfile(i_path):
            count+=1
        else:
            count+=count_file_scan(i_path)
    return count


    



file=r"D:\Y2\T1\PYTHON FOR CYBER\project\button"
print("Total of Scan:",count_file_scan(file))

removeMaleware("D:\Y2\T1\PYTHON FOR CYBER\project\Test")