from core.setting import MalwareDetection

class Scanner(MalwareDetection):
    def __init__ (self,path):
        super().__init__(path)
        self.path=path
        self.TotalFile=0
        self.scan_file=0
        self.Maleware=0
        self.ListMaleware=[]
    def scan(self):
        self.ListMaleware=self.check_folder(self.path)
        self.TotalFile=self.count()
        print("Total file :{}".format(self.TotalFile))
        print("file Virus:{}".format(self.ListMaleware))
        for i in self.ListMaleware:
            self.Maleware+=1
        print("File Scan: {}\nFile Virus:{}".format(self.TotalFile,self.Maleware))