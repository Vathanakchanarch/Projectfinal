from core.setting import MalwareDetection

class Scanner(MalwareDetection):
    # - Inherit scanning functionality from MalwareDetection
    # - Store path to scan
    # - Prepare counters and lists for scan results
    def __init__ (self,path):
        super().__init__(path)
        self.path=path
        self.TotalFile=0
        self.scan_file=0
        self.Maleware=0
        self.ListMaleware=[]
        # - Scan files and folders using inherited method
        # - Count total scanned files
        # - Count detected malware
        # - Display scan summary
    def scan(self):
        # Scan the path for malware
        self.ListMaleware=self.check_folder(self.path)
        # Get total number of scanned files
        self.TotalFile=self.count()
        # Count number of detected malware files
        for i in self.ListMaleware:
            self.Maleware+=1
        # Display scan results
        print("\n========== Scan Result ==========")
        print(f"Total Files Scanned : {self.TotalFile}")
        print(f"Detected Malware    : {len(self.ListMaleware)}")
        print(f"Malware List        : {self.ListMaleware}")
        print("=================================\n")
       