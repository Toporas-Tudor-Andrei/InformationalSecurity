import sys
from PyQt5.QtWidgets import QApplication, QDialog
from PyQt5 import uic


class MyDialog(QDialog):
    def __init__(self):
        super().__init__()

        # Load the .ui file
        uic.loadUi('../res/untitled.ui', self)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    dialog = MyDialog()
    dialog.show()
    sys.exit(app.exec_())
