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

def check_malware(filePath):
    hashOffile=get_hash(filePath)
    with open("virus.txt",'r') as fileVirus:    # get readlines file virus
        file=[line.strip() for line in fileVirus.readlines()] #delete /n
    with open("virusinfo.txt",'r') as f_info: # get read file virusinfor
        file_infor=[line.strip() for line in f_info.readlines()] 
    
    if hashOffile in file:
        h=file.index(hashOffile)
        print(file_infor[h])
    else :
        print("blue")
    
# print(get_hash("screen.jpg"))
check_malware("screen.jpg")

