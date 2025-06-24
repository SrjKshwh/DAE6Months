<<<<<<< HEAD
import sys
from PyQt6.QtWidgets import QApplication, QWidget, QGridLayout, QPushButton, QLineEdit, QVBoxLayout

def __init__(self):
   layout = QVBoxLayout()
   # Create a QLineEdit widget
   self.input_box = QLineEdit(self)
   self.input_box.setPlaceholderText("Enter your name...") # Optional placeholder text
   layout.addWidget(self.input_box)
   
   # Create a button to process the input
   self.submit_button = QPushButton("Submit", self)
   self.submit_button.clicked.connect(self.process_input)
   layout.addWidget(self.submit_button)

   self.setLayout(layout)

def process_input(self):
    entered_text = self.input_box.text()
    print(f"You entered: {entered_text}")
    # You can now use 'entered_text' for further processing in your application


def window():
   app = QApplication(sys.argv)
   win = QWidget()
   grid = QGridLayout()

   for i in range(1, 10):
      for j in range(1, 10):
         grid.addWidget(QPushButton("B" + str(i) + str(j)), i, j)

   win.setLayout(grid)
   win.setLayout(layout)
   win.setGeometry(100, 100, 200, 100)
   win.setWindowTitle("PyQt")
   win.show()
   sys.exit(app.exec())

if __name__ == '__main__':
   window()
=======
import tkinter as tk
from tkinter import font
import random
import string

#----------------------------------------LOGIC ON GUI INITIAL LOADING----------------------------------------------------
# getting random words from text file
i=1
rndWordList=[]
with open("C:/Users/saroj/OneDrive/Desktop/course/python_1/listTextFile.txt", "r") as file:
    allText = file.read()
    words = list(map(str, allText.split()))
    for i in range(7):
        randomWord=random.choice(words)
        if randomWord in rndWordList:
            randomWord=random.choice(words)
        else:
            rndWordList.append(randomWord)
print(rndWordList)


#----------------------------------------DEFINING FUNCTIONS---------------------------------------------------- 

# add user given words to random above list
def addToList():
    print("1--: %s\n2--: %s\n3--: %s" % (e1.get(), e2.get(), e3.get()))
    rndWordList.append(e1.get())
    rndWordList.append(e2.get())
    rndWordList.append(e3.get())
    print(rndWordList)
    listbox=tk.Listbox(master)
    for item in rndWordList:
        listbox.insert(tk.END, item)
    listbox.grid(row=8, column=1, padx=10, pady=10)
    #e1.grid_forget()
    #e2.grid_forget()
    #e3.grid_forget()
    button2.grid_forget()

#----------------------------------------CREATING GUI---------------------------------------------------- 
# creating main tkinter interface and dividing into left and right panel
master = tk.Tk()

left_frame = tk.Frame(master, width=400, height=400, bg='lightblue')
left_frame.grid(row=0, column=0, padx=20, pady=20)
right_frame = tk.Frame(master, width=400, height=400, bg='lightgray')
right_frame.grid(row=0, column=1, padx=20, pady=20)


default_font = font.Font(family="Arial", size=12)
# Set default font for Label, Entry and Button widgets
left_frame.option_add("*Label.Font", default_font)
right_frame.option_add("*Label.Font", default_font)
right_frame.option_add("*Button.Font", default_font)
right_frame.option_add("*Entry.Font", default_font)
right_frame.option_add("*Listbox.Font", default_font)

#--------------------------LEFT PANEL CONTENT STARTS------------------------------------------- 
matrixSize=5
rows = []
grid_cells = []

for r in range(matrixSize):
    for c in range(matrixSize):
        # word search logic
        random_char=random.choice(string.ascii_lowercase)
        #print(random_char)
        tk.Label(left_frame, text=random_char, padx=5, pady=5, bg='lightblue').grid(row=r, column=c)
        rows.append(random_char)
    print(rows)
    #print("\n")
grid_cells.append(rows)

print(grid_cells)

#--------------------------LEFT PANEL CONTENT ENDS--------------------------------------------- 



#--------------------------RIGHT PANEL CONTENT STARTS------------------------------------------- 
# creating labels for text box and adding to the grid
tk.Label(right_frame, text="1st word", bg='lightgray').grid(row=1)
tk.Label(right_frame, text="2nd word", bg='lightgray').grid(row=2)
tk.Label(right_frame, text="3rd word", bg='lightgray').grid(row=3)

# creating input boxes
e1 = tk.Entry(right_frame)
e2 = tk.Entry(right_frame)
e3 = tk.Entry(right_frame)

# adding input boxes to the grid
e1.grid(row=1, column=1)
e2.grid(row=2, column=1)
e3.grid(row=3, column=1)

# creating buttons and adding to the grid
button1=tk.Button(right_frame, text='Quit', command=master.quit)
button1.grid(row=6, column=1, padx=5, pady=5, sticky='ew')

button2=tk.Button(right_frame, text='Add to list', command=addToList)
button2.grid(row=5, column=1, padx=5, pady=5, sticky='ew')

#--------------------------RIGHT PANEL CONTENT ENDS------------------------------------------- 


tk.mainloop()
    
>>>>>>> master
