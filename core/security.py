import hashlib
class security:
    def __init__(self):
        self.User = r'D:\Y2\T1\PYTHON FOR CYBER\Projectstruct\DatabaseUser\Username.txt'
        self.Password = r'D:\Y2\T1\PYTHON FOR CYBER\Projectstruct\DatabaseUser\PasswordUser.txt'

    def hashes_password(self, pwd):
        return hashlib.sha256(pwd.encode()).hexdigest()

    def DatabaseUser(self):
        with open(self.User, 'r') as u:
            User = [line.strip() for line in u.readlines() if line.strip()]
        with open(self.Password, 'r') as p:
            Password = [line.strip() for line in p.readlines() if line.strip()]
        return User, Password

    def verify(self):
        pwd = input("Please Enter your password: ").strip()
        User, Password = self.DatabaseUser()
        
        if hashes_password(pwd) in Password:
            print("Access granted.\n")
            return True
        else:
            print("Wrong password!")
            return False



# E = security()
# Z, G = E.DatabaseUser()
# print(G)         
# result = E.verify()
# print(result)
