import os
from core.Quanratine import Quanrantine
import zipfile

class RemoveVirus(Quanrantine):
    def __init__(self):
        super().__init__(None)
        self.New_zip = self.toQuanrantine + ".tmp"

    def Remove(self):
        with zipfile.ZipFile(self.toQuanrantine, 'r') as z:
            listfile = z.namelist()
            if len(listfile) < 1:
                print("Don't have Virus!")
                return 1
            files = [n.strip() for n in listfile]
        print("Files virus:")
        for i in files:
            print(i)
        print("1.Remove specific file:")
        print("2.Remove all:")
        option=input("Enter your option:")

        if option=="1":
            index = int(input("Enter the number of the file to delete: "))
            delete_file = files[index]
            with zipfile.ZipFile(self.toQuanrantine, 'r') as z_in:
                with zipfile.ZipFile(self.New_zip, 'w') as z_out:
                    for i in files:
                        if i != delete_file:
                            z_out.writestr(i, z_in.read(i))
            os.remove(self.toQuanrantine)
            os.rename(self.New_zip, self.toQuanrantine)
            print(f"Removed: {delete_file}")
        elif option == '2':
            with zipfile.ZipFile(self.toQuanrantine, 'w') as z:
                z.writestr("","")
            print("All files removed!")
        else:
            print("Invalid option!")
