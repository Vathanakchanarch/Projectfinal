# import os
# import hashlib
# import zipfile

# zip_path = r"D:\Y2\T1\PYTHON FOR CYBER\Projectstruct\Quarantine.zip"

# with zipfile.ZipFile(zip_path,'a') as z:
#     names = z.namelist()        # all entries (files + folders)
#     print("Total entries:", len(names))

#     # If you only want files (exclude directory placeholders)
#     files = [n for n in names if not n.endswith('/')]
#     print("Total files:", len(files))

#     # Optional: print them
#     for name in files:
#         print(name)
#     os.remove(files[0])

# with zipfile.ZipFile("D:\Y2\T1\PYTHON FOR CYBER\Projectstruct\Quarantine.zip", "a", zipfile.ZIP_DEFLATED) as zipf:
#     zipf.write(r"D:\Y2\T1\PYTHON FOR CYBER\Projectstruct\tests\screen.jpg")

