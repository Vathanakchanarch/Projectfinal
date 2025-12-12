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
        for i in self.ListMaleware:
            self.Maleware+=1
        print("\n========== Scan Result ==========")
        print(f"Total Files Scanned : {self.TotalFile}")
        print(f"Detected Malware    : {len(self.ListMaleware)}")
        print(f"Malware List        : {self.ListMaleware}")
        print("=================================\n")
       