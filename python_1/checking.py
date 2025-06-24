from PyQt5.QtWidgets import QApplication, QWidget, QLineEdit, QVBoxLayout, QPushButton

class MyWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PyQt Input Box Example")
        self.setGeometry(100, 100, 300, 150)

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

if __name__ == "__main__":
    app = QApplication([])
    window = MyWindow()
    window.show()
    app.exec_()