import sys
from PyQt5.QtWidgets import QApplication, QDialog, QVBoxLayout, QPushButton, QLabel, QStackedWidget, QComboBox, \
    QFileDialog, QWidget


class MyDialog(QDialog):
    def __init__(self):
        super().__init__()

        self.stacked_widget = QStackedWidget()

        buttons_widget = QWidget()
        encode_button = QPushButton('Encode file')
        decode_button = QPushButton('Decode file')
        encode_button.setFixedSize(150, 50)
        decode_button.setFixedSize(150, 50)

        layout_buttons = QVBoxLayout()
        layout_buttons.addWidget(encode_button)
        layout_buttons.addWidget(decode_button)
        buttons_widget.setLayout(layout_buttons)

        encode_content_widget = QWidget()
        encode_content_layout = QVBoxLayout()

        select_algorithm_label = QLabel('Select an algorithm:')
        algorithm_dropdown = QComboBox()
        algorithm_dropdown.addItems(['AES', 'RSA', 'SHA-256'])
        self.algorithm_label = QLabel('')
        next_button = QPushButton('Next')
        encode_content_layout.addWidget(select_algorithm_label)
        encode_content_layout.addWidget(algorithm_dropdown)
        encode_content_layout.addWidget(self.algorithm_label)
        encode_content_layout.addWidget(next_button)
        encode_content_widget.setLayout(encode_content_layout)

        self.stacked_widget.addWidget(buttons_widget)
        self.stacked_widget.addWidget(encode_content_widget)

        encode_button.clicked.connect(self.show_encode_content)
        decode_button.clicked.connect(self.show_decode_content)
        next_button.clicked.connect(self.show_next_content)
        algorithm_dropdown.currentIndexChanged.connect(self.update_algorithm_label)

        layout = QVBoxLayout()
        layout.addWidget(self.stacked_widget)
        self.setLayout(layout)
        self.resize(400, 300)


    def show_next_content(self):
        self.stacked_widget.setCurrentIndex(2)

    def show_encode_content(self):
        self.stacked_widget.setCurrentIndex(1)

    def show_decode_content(self):
        file_dialog = QFileDialog(self)
        file_dialog.setWindowTitle("Select a file to decode")
        file_dialog.setFileMode(QFileDialog.ExistingFiles)
        if file_dialog.exec_():
            file_names = file_dialog.selectedFiles()
            print("Selected files:", file_names)

    def update_algorithm_label(self, index):
        algorithm = self.sender().currentText()
        self.algorithm_label.setText(f'Selected algorithm: {algorithm}')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    dialog = MyDialog()
    dialog.show()
    sys.exit(app.exec_())


