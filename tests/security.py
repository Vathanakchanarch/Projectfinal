import hashlib
class security:
    def __init__(self):
        self.User = r'D:\Y2\T1\PYTHON FOR CYBER\Projectstruct\DatabaseUser\Username.txt'
        self.Password = r'D:\Y2\T1\PYTHON FOR CYBER\Projectstruct\DatabaseUser\PasswordUser.txt'

    def hashes_password(self, pwd):
        return hashlib.sha256(pwd.encode()).hexdigest()

    def verify(self):
        pwd = input("Please Enter your password: ").strip()
        User, Password = self.DatabaseUser()
        
        if hashes_password(pwd) in Password:
            print("Access granted.\n")
            return True
        else:
            print("Wrong password!")
            return False



