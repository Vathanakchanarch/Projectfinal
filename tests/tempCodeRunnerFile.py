import os
import hashlib
import zipfile

zip_path = r"D:\Y2\T1\PYTHON FOR CYBER\Projectstruct\keylogger.zip"

with zipfile.ZipFile(zip_path) as z:
    names = z.namelist()        # all entries (files + folders)
    print("Total entries:", len(names))

    # If you only want files (exclude directory placeholders)
    files = [n for n in names if not n.endswith('/')]
    print("Total files:", len(files))

    # Optional: print them
    for name in files:
        print(name)

