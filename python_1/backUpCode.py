


rows=10
cols=10
grid_cells = []
for r in range(rows):
    row_cells = []
    for c in range(cols):
        cell_label = tk.Label(mainWindow, text="", width=4, height=2, relief="solid", borderwidth=1)
        cell_label.grid(row=r, column=c, padx=1, pady=1) # Place in the grid
        row_cells.append(cell_label)
    grid_cells.append(row_cells)

for r in range(rows):
    for c in range(cols):
            # word search logic
        grid_cells[r][c].config(text=random.choice(string.ascii_uppercase))

#mainWindow.mainloop()





import tkinter as tk
import random
import string
import os
os.environ['TK_SILENCE_DEPRECATION'] = '1'


def getInput():
    givenInput=inputBox.get()
    print("--", givenInput)


def get_entry_text():
    """Retrieves text from the Entry widget and updates the label."""
    entered_text = entry_widget.get()
    output_label.config(text=f"Hello, {entered_text}!")


i=1
rndWordList=[]
with open("/Users/adult/Desktop/SrjKshwh/python_1/listTextFile.txt", "r") as file:
    allText = file.read()
    words = list(map(str, allText.split()))
    for i in range(7):
        randomWord=random.choice(words)
        if randomWord in rndWordList:
            randomWord=random.choice(words)
        else:
            rndWordList.append(randomWord)
print(rndWordList)

mainWindow=tk.Tk()
mainWindow.title("Word Search")
mainWindow.geometry("300x150")


inputBox=tk.Entry(mainWindow, textvariable="ssss", width=30)
inputBox.pack(padx=10, pady=10)

submitButton=tk.Button(mainWindow, text="Submit", command=getInput)
submitButton.pack()







# Create an Entry widget
entry_widget = tk.Entry(mainWindow, width=30)
entry_widget.pack(pady=10)

# Create a Button to trigger text retrieval
submit_button = tk.Button(mainWindow, text="Submit", command=get_entry_text)
submit_button.pack()

# Create a Label to display the output
output_label = tk.Label(mainWindow, text="")
output_label.pack(pady=10)

#mainWindow.mainloop()


import sys
from PyQt6.QtWidgets import QApplication, QWidget, QGridLayout, QPushButton
def window():
   app = QApplication(sys.argv)
   win = QWidget()
   grid = QGridLayout()

   for i in range(1, 10):
      for j in range(1, 10):
         grid.addWidget(QPushButton("B" + str(i) + str(j)), i, j)

   win.setLayout(grid)
   win.setGeometry(100, 100, 200, 100)
   win.setWindowTitle("PyQt")
   win.show()
   sys.exit(app.exec())

if __name__ == '__main__':
   window()