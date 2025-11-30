from tkinter import *
from PIL import Image, ImageTk


window = Tk()
window.title("Conronavirus") # set title 
window.geometry("900x500") #set size

# window.minsize()
# window.maxsize()
winframe= Frame(window,width="180",height="500",bg="gray",borderwidth=1)
winframe.pack()
winframe.pack_propagate(0)
def homepage():
    global homeButtomImg
    
    img = Image.open(r"D:\Y2\T1\PYTHON FOR CYBER\project\button\White theme\Buttons\home.png")
    img = img.resize((150, 40), Image.LANCZOS)

    homeButtomImg = ImageTk.PhotoImage(img)

    homeButton = Label(winframe, image=homeButtomImg, bg="blue",cursor="hand2")
   
    homeButton.place(x=10, y=50)
    
def scanpage():
    global scanButtomImg
    
    img = Image.open(r"D:\Y2\T1\PYTHON FOR CYBER\project\button\White theme\Buttons\scan.png")
    img = img.resize((150, 40), Image.LANCZOS)

    scanButtomImg = ImageTk.PhotoImage(img)

    scanbutton = Label(winframe, image=scanButtomImg, bg="blue",cursor="hand2")
    scanbutton.place(x=10, y=100)

homepage()
scanpage()


window.mainloop()