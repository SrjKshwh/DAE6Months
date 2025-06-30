import random
import string
<<<<<<< HEAD
rowCount=4
colCount=4
=======
matrixSize=5
>>>>>>> master

rows = []
grid_cells = []

<<<<<<< HEAD
for r in range(rowCount):
    for c in range(colCount):
=======
for r in range(matrixSize):
    for c in range(matrixSize):
>>>>>>> master
        # word search logic
        random_char=random.choice(string.ascii_lowercase)
        #print(random_char)
        rows.append(random_char)
    print(rows)
<<<<<<< HEAD
    print("\n")
grid_cells.append(rows)


=======
    #print("\n")
grid_cells.append(rows)

print(grid_cells)
>>>>>>> master
