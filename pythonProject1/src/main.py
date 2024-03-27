import os
import sys
from PyQt5.QtWidgets import *

from CryptoWrapper.CryptoWrapper import algRepo
from criptograpy_module.Cryptography import Cryptography
from criptograpy_module.KeyGenerator import KeyGenerator


class MyDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.encode_button_checked = False
        self.selected_file_path = None
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Something')

        self.encode_button = QPushButton('Encode', self)
        self.encode_button.setCheckable(True)
        self.decode_button = QPushButton('Decode', self)
        self.decode_button.setCheckable(True)

        self.encode_button.setFixedSize(100, 30)
        self.decode_button.setFixedSize(100, 30)

        vbox = QVBoxLayout()
        vbox.addWidget(self.encode_button)
        vbox.addWidget(self.decode_button)

        self.encode_button.clicked.connect(self.encode_action)
        self.decode_button.clicked.connect(self.decode_action)

        self.setLayout(vbox)
        self.setFixedSize(700, 800)

    def encode_action(self):
        if not self.encode_button_checked:
            self.encode_button_checked = True
            self.decode_button.setChecked(False)
            frameworks = set()

            self.algorithm_combo_box = QComboBox(self)
            algorithms = algRepo.findAll()
            for algorithm in algorithms:
                self.algorithm_combo_box.addItem(algorithm.name)
                frameworks.add(algorithm.framework)
            vbox = self.layout()
            vbox.addWidget(self.algorithm_combo_box)

            self.framework_combo_box = QComboBox(self)
            for framework in frameworks:
                self.framework_combo_box.addItem(framework)
            vbox.addWidget(self.framework_combo_box)
            self.generate_button = QPushButton('Generate', self)
            self.generate_button.setFixedSize(100, 30)
            vbox.addWidget(self.generate_button)
            self.generate_button.setVisible(False)

            self.private_key_label = QLabel("", self)
            vbox.addWidget(self.private_key_label)
            self.private_key_label.setVisible(False)

            self.public_key_label = QLabel("", self)
            vbox.addWidget(self.public_key_label)
            self.public_key_label.setVisible(False)
            self.browse_button = QPushButton('Browse', self)
            self.browse_button.setFixedSize(100, 30)
            vbox.addWidget(self.browse_button)
            self.browse_button.setVisible(False)

            self.file_label = QLabel("", self)
            vbox.addWidget(self.file_label)
            self.file_label.setVisible(False)
            self.performance_checkbox = QCheckBox('Record Performance', self)
            vbox.addWidget(self.performance_checkbox)
            self.performance_checkbox.setVisible(False)
            self.save_button = QPushButton('Save', self)
            self.save_button.setFixedSize(100, 30)
            vbox.addWidget(self.save_button)
            self.save_button.setVisible(False)
            self.framework_combo_box.activated.connect(self.show_generate_key)
            self.generate_button.clicked.connect(self.generate_key)

    def decode_action(self):
        if hasattr(self, 'algorithm_combo_box'):
            self.algorithm_combo_box.deleteLater()
            del self.algorithm_combo_box

            self.encode_button_checked = False
            if hasattr(self, 'browse_button'):
                self.browse_button.setVisible(False)
            if hasattr(self, 'file_label'):
                self.file_label.setVisible(False)
            if hasattr(self, 'private_key_label'):
                self.private_key_label.setVisible(False)
            if hasattr(self, 'public_key_label'):
                self.public_key_label.setVisible(False)
            if hasattr(self, 'performance_checkbox'):
                self.performance_checkbox.setVisible(False)
            if hasattr(self, 'generate_button'):
                self.generate_button.setVisible(False)
            if hasattr(self, 'framework_combo_box'):
                self.framework_combo_box.setVisible(False)
            if hasattr(self, 'save_button'):
                self.save_button.setVisible(False)

    def show_generate_key(self):
        self.generate_button.setVisible(True)

    def generate_key(self):
        algorithm_name = self.algorithm_combo_box.currentText()
        framework_name = self.framework_combo_box.currentText()

        if algorithm_name == "AES" and framework_name == "PyCryptodome":
            key = KeyGenerator.generate_aes_key()
            self.private_key_label.setText("Generated AES key: " + key)
            self.private_key_label.setVisible(True)
        elif algorithm_name == "RSA" and framework_name == "PyCryptodome":
            private_key, public_key = KeyGenerator.generate_rsa_key_pair()
            self.private_key_label.setText("Generated RSA private key:\n" + private_key.decode("utf-8"))
            self.private_key_label.setVisible(True)
            self.public_key_label.setText("Generated RSA public key:\n" + public_key.decode("utf-8"))
            self.public_key_label.setVisible(True)
            self.browse_button.setVisible(True)
            self.browse_button.clicked.connect(self.browse_files)
            return public_key
        self.browse_button.setVisible(True)
        self.browse_button.clicked.connect(self.browse_files)

    def browse_files(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.selected_file_path = file_path
            self.file_label.setText(f"Selected file: {file_path}")
            self.file_label.setVisible(True)
            self.performance_checkbox.setVisible(True)
            self.save_button.setVisible(True)
            self.save_button.clicked.connect(self.save_file)

    def save_file(self):
        algorithm_name = self.algorithm_combo_box.currentText()
        framework_name = self.framework_combo_box.currentText()
        file_path, _ = QFileDialog.getSaveFileName(self, "Save File", "", "All Files (*);;Text Files (*.txt)")
        if file_path:
            plaintext = "ok"  # de preluat din fisier

            if algorithm_name == "AES" and framework_name == "PyCrypto":
                key = KeyGenerator.generate_aes_key()
                ciphertext = Cryptography.encrypt_aes(plaintext, key)

            elif algorithm_name == "RSA" and framework_name == "PyCrypto":
                public_key_pem = self.generate_key()
                ciphertext = Cryptography.encrypt_rsa(plaintext, public_key_pem)
                print(repr(ciphertext))


if __name__ == '__main__':
    app = QApplication(sys.argv)
    dialog = MyDialog()
    dialog.show()
    sys.exit(app.exec_())

