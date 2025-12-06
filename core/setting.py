import os
import hashlib

class MalwareDetection:
    def __init__(self, path):
        self.path = path
        self.virus_hash_file = r"D:\Y2\T1\PYTHON FOR CYBER\Projectstruct\database\virusHash.txt"
        self.virus_info_file = r"D:\Y2\T1\PYTHON FOR CYBER\Projectstruct\database\virusInfo.txt"
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
