import os
import hashlib
import magic
import pyfiglet
import requests

# # def display_banner():
# #     banner = pyfiglet.figlet_format("CovidVirus")
# #     print(banner)
# # display_banner()
# print("develop by team 2!")
# get hash from file
def get_hash(file_path):
    with open(file_path,"rb") as f:
        file=f.read()
        hash_sh256=hashlib.sha256(file).hexdigest()
    return hash_sh256
# compare hash


#Scan by Hash
def check_malware(filePath):
    hashOffile=get_hash(filePath)
    with open("virus.txt",'r') as fileVirus:    # get readlines file virus
        file=[line.strip() for line in fileVirus.readlines()] #delete /n
    with open("virusinfo.txt",'r') as f_info: # get read file virusinfor
        file_infor=[line.strip() for line in f_info.readlines()] 
    
    if hashOffile in file:
        h=file.index(hashOffile)
        return file_infor[h]
    else:
        return 0
    # else :
    #     print("blue")
# print(get_hash("screen.jpg"))
# check_malware("screen.jpg")

# Check in folder if have file that have virus append into MalleWareName.....
MalewareName=[]
def check_folder(path):
    dirs_list=os.listdir(path)
    FileInList=""
    for i in dirs_list:
        FileInList= path + "\\" + i
        if check_malware(FileInList) != 0:
            MalewareName.append(check_malware(FileInList))

path="D:\Y2\T1\PYTHON FOR CYBER\project\Test"
check_folder(path)
print(MalewareName)



def removeMaleware(path):
    check_folder(path)
    for i in MalewareName:
        try:
            os.remove(i)
            print("Removed malware file: {}".format(i))
        except Exception as e :
            print("Error removing {0}: {1}".format(i,e))
    