<<<<<<< HEAD
from core.setting import display_banner
from core.scanner import Scanner
from core.Quanratine import Quanrantine
from core.Removevirus import RemoveVirus


display_banner()

while(True):
    print("Please Choose Your options: ")
    print("1.Scan file🦠:")
    print("2.Quarantine🔐:")
    print("3.Remove Virus❌:")
    print("4.Exit")
    Options=input("Enter your Options[1-4]:")
    
    if Options=="1":
        print("Welcome To Scan file:")
        file=input("Enter file here:")
        S=Scanner(file)
        S.scan()
        choice=input("Do you want to contiue[y/n]?")
        if choice=='y'or choice=='Y':
            continue
        elif choice=='N' or choice=='n':
            break
        
    if Options == "2":
        print("Quanrantine file ")
        file=input("Enter your File:")
        Q=Quanrantine(file)
        Q.Movefile()
        choice=input("Do you want to contiue[y/n]?")
        if choice=='y'or choice=='Y':
            continue
        elif choice=='N' or choice=='n':
            break
    if Options == "3" :
        R=RemoveVirus()
        R.Remove()
        choice=input("Do you want to contiue[y/n]?")
        if choice=='y'or choice=='Y':
            continue
        elif choice=='N' or choice=='n':
            break
    if Options == "4" :
        print("Thank you!")
        break   
    else:
=======
from core.setting import display_banner
from core.scanner import Scanner
from core.Quanratine import Quanrantine
from core.Removevirus import RemoveVirus


display_banner()

while(True):
    print("Please Choose Your options: ")
    print("1.Scan file🦠:")
    print("2.Quarantine🔐:")
    print("3.Remove Virus❌:")
    print("4.Exit")
    Options=input("Enter your Options[1-4]:")
    
    if Options=="1":
        print("Welcome To Scan file:")
        file=input("Enter file here:")
        S=Scanner(file)
        S.scan()
        choice=input("Do you want to contiue[y/n]?")
        if choice=='y'or choice=='Y':
            continue
        elif choice=='N' or choice=='n':
            break
        
    if Options == "2":
        print("Quanrantine file ")
        file=input("Enter your File:")
        Q=Quanrantine(file)
        Q.Movefile()
        choice=input("Do you want to contiue[y/n]?")
        if choice=='y'or choice=='Y':
            continue
        elif choice=='N' or choice=='n':
            break
    if Options == "3" :
        R=RemoveVirus()
        R.Remove()
        choice=input("Do you want to contiue[y/n]?")
        if choice=='y'or choice=='Y':
            continue
        elif choice=='N' or choice=='n':
            break
    if Options == "4" :
        print("Thank you!")
        break   
    else:
>>>>>>> b1f231e179fd4c4e6ef2898696a16fd89b794024
        print("Please Try again! ")