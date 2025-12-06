# import hashlib
# from security import security


# class Registor(security):
#     Password=r"D:\Y2\T1\PYTHON FOR CYBER\Projectstruct\DatabaseUser\PasswordUser.txt"
#     User=r"D:\Y2\T1\PYTHON FOR CYBER\Projectstruct\DatabaseUser\Username.txt"
#     def __init__(self,Username,Password):
#         super().__init__()
#         self.Username=Username
#         self.__password=Password
#     def encode(self):
#         return self.hashes_password(self.__password)
#     def storeUsername(self):
#         with open(Registor.Password,'a') as p:
#             p.write("\n")
#             p.write(self.encode())
#         with open(Registor.User,'a') as u:
#             u.write("\n")
#             u.write(self.Username)

# C=Registor("nakk","123")
# C.storeUsername()
# # def Manu():
#     print("1. Login")
#     print("\n2. Registor\n")
#     print("Exit")
#     options=int("Enter your Options:")
#     if options=='1':
#         Username=int('Enter your Username:')
#         Password=int('Enter your password:')
#         security=security()
#         user,pwd=security.DatabaseUser()
#         EncodPasss=security.hashes_password(Password)
#         if Username in user:
#             index=user.index(Username)
#             if Password == pwd[index]:
#                 print("Login successful!\n")
#                 return True
#             else :
#                 print ("Wrong Password!\n")
#         else:
#             print("Username not valid!")
#     elif options=='2':
#         Username=int('Enter your Username:')
#         Password=int('Enter your Password:')
        