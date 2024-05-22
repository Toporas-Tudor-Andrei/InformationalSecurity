import binascii

from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
import sys
import os
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from pythonProject1.CryptoWrapper.CryptoWrapper import encode_with_performance_measurment_simetric, \
    encode_with_performance_measurment_asimetric, getFrameworks, getAlgorithmModes, getAlgorithmByFramework, \
    getAlgorithmKeysLenghts, decode_ciphertext_simetric, decode_ciphertext_asimetric, perfData, logsProcessing
from pythonProject1.criptograpy_module.KeyGenerator import KeyGenerator





class EncodePage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.selected_algorithm = None
        self.is_symmetric = False
        self.selected_file_content = None
        layout = QVBoxLayout()
        self.group_box = QGroupBox()
        self.group_box.setMaximumHeight(100)
        self.group_box.setStyleSheet("QGroupBox { border: 2px dashed red; }")

        layout_group_box = QVBoxLayout()
        self.label = QLabel('Drag and drop a file here or click to select')
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setAcceptDrops(True)
        self.file_icon_label = QLabel()
        self.file_icon_label.setAlignment(Qt.AlignCenter)
        layout_group_box.addWidget(self.file_icon_label)
        layout_group_box.addWidget(self.label)
        self.group_box.setLayout(layout_group_box)
        layout.addWidget(self.group_box)
        self.label.mousePressEvent = self.select_file
        self.label.dragEnterEvent = self.drag_enter_event
        self.label.dropEvent = self.drop_event
        self.mode_combo = QComboBox()
        self.private_key_label = QLineEdit(self)
        self.private_key_label.setVisible(False)

        self.public_key_label = QLineEdit(self)
        self.public_key_label.setVisible(False)
        self.algorithm_combo = QComboBox()
        #       self.symmetric_checkbox = QCheckBox("I want my algorithm symmetric")
        #        self.symmetric_checkbox.stateChanged.connect(self.update_symmetric_variable)

        self.framework_combo = QComboBox()

        self.key_length_combo = QComboBox()
        self.generate_key_button = QPushButton('Generate Key')
        self.generate_key_button.clicked.connect(self.generate_key)
        self.key_textbox = QTextEdit()

        self.populate_comboboxes()

        algorithm_layout = QHBoxLayout()

        algorithm_layout.addWidget(self.algorithm_combo)
        # algorithm_layout.addWidget(self.symmetric_checkbox)
        layout.addWidget(self.framework_combo)
        layout.addLayout(algorithm_layout)
        layout.addWidget(self.key_length_combo)
        layout.addWidget(self.mode_combo)
        layout.addWidget(self.generate_key_button)
        layout.addWidget(self.private_key_label)
        layout.addWidget(self.public_key_label)

        back_button = QPushButton('Back')
        back_button.clicked.connect(self.parent().back_to_main)
        save_button = QPushButton('Save')
        save_button.clicked.connect(self.save_function)

        layout.addWidget(back_button, alignment=Qt.AlignLeft)
        layout.addWidget(save_button, alignment=Qt.AlignRight)

        self.algorithm_combo.currentIndexChanged.connect(self.update_mode_combo)
        self.setLayout(layout)

        self.apply_styles()

    def save_function(self):
        plaintext = self.selected_file_content
        framework = self.framework_combo.currentText()
        algorithm = self.algorithm_combo.currentText()
        key1 = bytes.fromhex(self.private_key_label.text())
        mode = self.mode_combo.currentText()
        print(algorithm)
        try:
            if algorithm != 'RSA':
                self.parent().selected_algorithm = algorithm
                ciphertext = encode_with_performance_measurment_simetric(plaintext, framework, algorithm, key1, mode)
            else:
                self.parent().selected_algorithm = algorithm
                key2 = bytes.fromhex(self.public_key_label.text())
                ciphertext = encode_with_performance_measurment_asimetric(plaintext, framework, algorithm, key2, key1)

            print("Key 1:", key1)
            if algorithm == 'RSA':
                print("Key 2:", key2)
            print("Ciphertext:", ciphertext)

            file_path, _ = QFileDialog.getSaveFileName(self, 'Save File')
            print("Cybertext_scris", ciphertext)
            if file_path:
                with open(file_path, 'wb') as file:
                    file.write(ciphertext)
        except Exception as e:
            print("An error occurred:", e)

    def generate_key(self):
        algorithm_name = self.algorithm_combo.currentText()
        key_length = self.key_length_combo.currentText()

        if algorithm_name != 'RSA':
            if key_length == '256':
                key = KeyGenerator.generate_256_key()
                self.private_key_label.setText(key.hex())
                self.private_key_label.setVisible(True)

            elif key_length == '192':
                key = KeyGenerator.generate_192_key()
                self.private_key_label.setText(key.hex())
                self.private_key_label.setVisible(True)

            elif key_length == '128':
                key = KeyGenerator.generate_128_key()
                self.private_key_label.setText(key.hex())
                self.private_key_label.setVisible(True)

            elif key_length == '64':
                key = KeyGenerator.generate_64_key()
                self.private_key_label.setText(key.hex())
                self.private_key_label.setVisible(True)

        else:
            private_key, public_key = KeyGenerator.generate_rsa_key_pair()
            self.private_key_label.setText(private_key.hex())
            self.private_key_label.setVisible(True)
            self.public_key_label.setText(public_key.hex())
            self.public_key_label.setVisible(True)

    def apply_styles(self):
        combobox_style = """
            QComboBox {
                border: 2px solid #4A90E2;
                border-radius: 5px;
                padding: 2px 8px; 
                background-color: #FFFFFF; 
                selection-background-color: #4A90E2;
                color: #000000; 
                font-size: 12px; 
            }
            QComboBox::drop-down {
                border: none; 
            }
        """
        self.algorithm_combo.setStyleSheet(combobox_style)
        self.framework_combo.setStyleSheet(combobox_style)
        self.key_length_combo.setStyleSheet(combobox_style)
        self.mode_combo.setStyleSheet(combobox_style)

        checkbox_style = """
                QCheckBox {
                    spacing: 2px; 
                    color: #000000; 
                    font-size: 12px;
                }
                QCheckBox::indicator {
                    width: 16px; 
                    height: 16px; 
                }
                QCheckBox::indicator:checked {
                    image: url("C:/Users/andra/Desktop/AN IV/sem 2/SI/InformationalSecurity/pythonProject1/assets/select.png"); 
                }
            """
        #  self.symmetric_checkbox.setStyleSheet(checkbox_style)
        lineedit_style = """
                        QLineEdit {
                            border: 2px solid #808080; 
                            border-radius: 5px;
                            padding: 5px; 
                            font-size: 12px; 
                            color: #000000; 
                        }

                    """
        self.private_key_label.setStyleSheet(lineedit_style)
        self.public_key_label.setStyleSheet(lineedit_style)

    def populate_comboboxes(self):
        frameworks = getFrameworks()
        self.framework_combo.addItems(sorted(list(frameworks)))
        self.framework_combo.currentIndexChanged.connect(self.update_algorithm_combo)
        self.update_algorithm_combo(0)
        self.update_mode_combo(0)

    def update_mode_combo(self, index):
        self.mode_combo.clear()
        framework = self.framework_combo.currentText()
        algorithm_name = self.algorithm_combo.currentText()
        modes = getAlgorithmModes(framework, algorithm_name)
        self.mode_combo.addItems(sorted(modes))

    def update_algorithm_combo(self, index):
        self.algorithm_combo.clear()
        framework = self.framework_combo.currentText()
        algorithms = getAlgorithmByFramework(framework)
        algorithm_names = set(map(lambda x: x.name, algorithms))

        self.algorithm_combo.addItems(sorted(algorithm_names))
        self.algorithm_combo.currentIndexChanged.connect(self.update_key_combo)
        self.update_key_combo(0)
        self.selected_algorithm = self.algorithm_combo.currentText()

    def update_key_combo(self, index):
        self.key_length_combo.clear()
        framework = self.framework_combo.currentText()
        algorithm_name = self.algorithm_combo.currentText()
        key_lengths = getAlgorithmKeysLenghts(framework, algorithm_name)
        key_lengths = sorted(map(int, key_lengths))
        key_lengths = list(map(str, key_lengths))
        self.key_length_combo.addItems(key_lengths)

    def select_file(self, event):
        filename, _ = QFileDialog.getOpenFileName(self, 'Select File')
        if filename:
            file_info = QFileInfo(filename)
            file_icon = QFileIconProvider().icon(file_info)
            self.file_icon_label.setPixmap(file_icon.pixmap(40, 40))

            self.label.setText(f'{file_info.fileName()}')
            with open(filename, 'r') as file:
                self.selected_file_content = file.read()

    def drag_enter_event(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def drop_event(self, event):
        if event.mimeData().hasUrls():
            event.setDropAction(Qt.CopyAction)
            event.accept()
            for url in event.mimeData().urls():
                file_path = url.toLocalFile()
                file_info = QFileInfo(file_path)
                file_icon = QFileIconProvider().icon(file_info)
                self.file_icon_label.setPixmap(file_icon.pixmap(40, 40))
                self.label.setText(file_info.fileName())
                with open(file_path, 'r') as file:
                    self.selected_file_content = file.read()


class DecodePage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.selected_algorithm = None
        self.selected_file_extension = None

        self.selected_file_content2 = None
        layout = QVBoxLayout()
        self.group_box = QGroupBox()
        self.group_box.setMaximumHeight(100)
        self.group_box.setStyleSheet("QGroupBox { border: 2px dashed red; }")

        layout_group_box = QVBoxLayout()
        self.label = QLabel('Drag and drop a file here or click to select')
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setAcceptDrops(True)
        self.file_icon_label = QLabel()
        self.file_icon_label.setAlignment(Qt.AlignCenter)
        layout_group_box.addWidget(self.file_icon_label)
        layout_group_box.addWidget(self.label)
        self.group_box.setLayout(layout_group_box)
        layout.addWidget(self.group_box)
        self.label.mousePressEvent = self.select_file
        self.label.dragEnterEvent = self.drag_enter_event
        self.label.dropEvent = self.drop_event

        self.save_button = QPushButton('Save Decrypted File')
        self.save_button.clicked.connect(self.save_decrypted_file)
        layout.addWidget(self.save_button)

        back_button = QPushButton('Back')
        back_button.clicked.connect(self.parent().back_to_main)

        layout.addWidget(back_button, alignment=Qt.AlignRight)
        self.setLayout(layout)

    def select_file(self, event):
        filename, _ = QFileDialog.getOpenFileName(self, 'Select File')
        if filename:
            file_info = QFileInfo(filename)
            file_icon = QFileIconProvider().icon(file_info)
            self.file_icon_label.setPixmap(file_icon.pixmap(40, 40))
            self.label.setText(f'{file_info.fileName()}')

            self.selected_file_extension = file_info.suffix()

            with open(filename, 'rb') as file:
                self.selected_file_content2 = file.read()

    def drag_enter_event(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def drop_event(self, event):
        if event.mimeData().hasUrls():
            event.setDropAction(Qt.CopyAction)
            event.accept()
            for url in event.mimeData().urls():
                file_path = url.toLocalFile()
                file_info = QFileInfo(file_path)
                file_icon = QFileIconProvider().icon(file_info)
                self.file_icon_label.setPixmap(file_icon.pixmap(40, 40))
                self.label.setText(file_info.fileName())


    def save_decrypted_file(self):
        try:
            if self.parent().selected_algorithm == 'RSA':
                key, plaintext = decode_ciphertext_asimetric(self.selected_file_content2)
            else:
                key, plaintext = decode_ciphertext_simetric(self.selected_file_content2)

            file_path, _ = QFileDialog.getSaveFileName(self, 'Save File')
            if file_path:
                with open(file_path, 'w') as file:
                    file.write(plaintext)
        except Exception as e:
            print("An error occurred:", e)

class PerformancesPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout()


        self.mode_combo = QComboBox()
        self.algorithm_combo = QComboBox()
        self.framework_combo = QComboBox()
        self.key_length_combo = QComboBox()
        self.populate_comboboxes()
        algorithm_layout = QHBoxLayout()

        algorithm_layout.addWidget(self.algorithm_combo)
        layout.addWidget(self.framework_combo)
        layout.addLayout(algorithm_layout)
        layout.addWidget(self.key_length_combo)
        layout.addWidget(self.mode_combo)

        self.target_combo = QComboBox()
        self.target_combo.addItems(["enc", "dec", "diff"])

        self.operation_combo = QComboBox()
        self.operation_combo.addItems(["avg", "min", "max"])

        layout.addWidget(self.target_combo)
        layout.addWidget(self.operation_combo)

        self.result_label = QLabel()
        layout.addWidget(self.result_label)


        self.calculate_button = QPushButton("Calculate")
        self.calculate_button.clicked.connect(self.calculate_performance)
        layout.addWidget(self.calculate_button)

        self.table_widget = QTableWidget()
        layout.addWidget(self.table_widget)



        back_button = QPushButton('Back')
        back_button.clicked.connect(self.parent().back_to_main)

        layout.addWidget(back_button, alignment=Qt.AlignLeft)

        self.setLayout(layout)

        self.apply_styles()

        headers = ['ID', 'Encoding Time', 'Decoding Time', 'Memory Usage Enc', 'Memory Usage Dec','File ID', 'Algorithm ID', 'File Size']
        self.table_widget.setColumnCount(len(headers))
        self.table_widget.setHorizontalHeaderLabels(headers)

    def apply_styles(self):
        combobox_style = """
            QComboBox {
                border: 2px solid #4A90E2;
                border-radius: 5px;
                padding: 2px 8px; 
                background-color: #FFFFFF; 
                selection-background-color: #4A90E2;
                color: #000000; 
                font-size: 12px; 
            }
            QComboBox::drop-down {
                border: none; 
            }
        """
        self.algorithm_combo.setStyleSheet(combobox_style)
        self.framework_combo.setStyleSheet(combobox_style)
        self.key_length_combo.setStyleSheet(combobox_style)
        self.mode_combo.setStyleSheet(combobox_style)
        self.operation_combo.setStyleSheet(combobox_style)
        self.target_combo.setStyleSheet(combobox_style)

        button_style = """
                   QPushButton {
                       padding: 8px 16px;
                       font-size: 14px;
                       background-color: #4A90E2;
                       color: #FFFFFF;
                       border: none;
                       border-radius: 5px;
                   }
                   QPushButton:hover {
                       background-color: #357AE8;
                   }
               """
        self.calculate_button.setStyleSheet(button_style)

    def calculate_performance(self):
        target = self.target_combo.currentText()
        operation = self.operation_combo.currentText()
        algorithm = self.algorithm_combo.currentText()
        framework = self.framework_combo.currentText()
        mode = self.mode_combo.currentText() or None
        key_length = self.key_length_combo.currentText() or None

        performance_data = perfData(alg=algorithm, framework=framework, mode=mode, keyLength=key_length)
        result = logsProcessing(performance_data, operation, target)

        if operation == "avg":
            self.result_label.setText(f"Average: {result}")
        elif operation == "min":
            self.result_label.setText(f"Minimum: {result}")
        elif operation == "max":
            self.result_label.setText(f"Maximum: {result}")

        self.update_performance_table(performance_data)

        all_algorithms = ['BF', 'RSA','3DES', 'DES', 'AES']

        all_mem_usage_enc_data = []
        all_mem_usage_dec_data = []
        all_encoding_time_data = []
        all_decoding_time_data = []

        for alg in all_algorithms:
            alg_performance_data = perfData(alg=alg)

            mem_u_enc_data = sorted(alg_performance_data, key=lambda it: it.bytes)
            mem_u_dec_data = sorted(alg_performance_data, key=lambda it: it.bytes)
            time_e_data = sorted(alg_performance_data, key=lambda it: it.bytes)
            time_d_data = sorted(alg_performance_data, key=lambda it: it.bytes)

            mem_usage_enc_data = [log.mem_usage_enc for log in mem_u_enc_data]
            bytes_data_m_e = [log.bytes for log in mem_u_enc_data]
            all_mem_usage_enc_data.append((mem_usage_enc_data, bytes_data_m_e, alg))

            mem_usage_dec_data = [log.mem_usage_dec for log in mem_u_dec_data]
            bytes_data_m_d = [log.bytes for log in mem_u_dec_data]
            all_mem_usage_dec_data.append((mem_usage_dec_data, bytes_data_m_d, alg))

            encoding_time_data = [log.encoding_time for log in time_e_data]
            bytes_data_t_e = [log.bytes for log in time_e_data]
            all_encoding_time_data.append((encoding_time_data, bytes_data_t_e, alg))

            decoding_time_data = [log.decoding_time for log in time_d_data]
            bytes_data_t_d = [log.bytes for log in time_d_data]
            all_decoding_time_data.append((decoding_time_data, bytes_data_t_d, alg))

        fig, axs = plt.subplots(2, 2, figsize=(12, 10))

        for mem_usage_enc_data, bytes_data_m_e, alg in all_mem_usage_enc_data:
            axs[0, 0].plot(bytes_data_m_e, mem_usage_enc_data, marker='o', linestyle='-')
            axs[0, 0].scatter(bytes_data_m_e, mem_usage_enc_data, label=alg)
        axs[0, 0].set_xlabel('Bytes')
        axs[0, 0].set_ylabel('Memory Usage (Encryption)')
        axs[0, 0].grid(True)
        axs[0, 0].legend()

        for mem_usage_dec_data, bytes_data_m_d, alg in all_mem_usage_dec_data:
            axs[0, 1].plot(bytes_data_m_d, mem_usage_dec_data, marker='o', linestyle='-')
            axs[0, 1].scatter(bytes_data_m_d, mem_usage_dec_data, label=alg)
        axs[0, 1].set_xlabel('Bytes')
        axs[0, 1].set_ylabel('Memory Usage (Decryption)')
        axs[0, 1].grid(True)
        axs[0, 1].legend()

        for encoding_time_data, bytes_data_t_e, alg in all_encoding_time_data:
            axs[1, 0].plot(bytes_data_t_e, encoding_time_data, marker='o', linestyle='-')
            axs[1, 0].scatter(bytes_data_t_e, encoding_time_data, label=alg)
        axs[1, 0].set_xlabel('Bytes')
        axs[1, 0].set_ylabel('Encoding Time')
        axs[1, 0].grid(True)
        axs[1, 0].legend()

        for decoding_time_data, bytes_data_t_d, alg in all_decoding_time_data:
            axs[1, 1].plot(bytes_data_t_d, decoding_time_data, marker='o', linestyle='-')
            axs[1, 1].scatter(bytes_data_t_d, decoding_time_data, label=alg)
        axs[1, 1].set_xlabel('Bytes')
        axs[1, 1].set_ylabel('Decoding Time')
        axs[1, 1].grid(True)
        axs[1, 1].legend()

        plt.tight_layout()
        plt.show()

    def update_performance_table(self, performance_data):
        self.table_widget.clearContents()

        num_rows = len(performance_data)
        self.table_widget.setRowCount(num_rows)
        num_cols = 8
        self.table_widget.setColumnCount(num_cols)

        for row, log in enumerate(performance_data):
            self.table_widget.setItem(row, 0, QTableWidgetItem(str(log.id)))
            self.table_widget.setItem(row, 1, QTableWidgetItem(str(log.encoding_time)))
            self.table_widget.setItem(row, 2, QTableWidgetItem(str(log.decoding_time)))
            self.table_widget.setItem(row, 3, QTableWidgetItem(str(log.mem_usage_enc)))
            self.table_widget.setItem(row, 4, QTableWidgetItem(str(log.mem_usage_dec)))
            self.table_widget.setItem(row, 5, QTableWidgetItem(str(log.file_id)))
            self.table_widget.setItem(row, 6, QTableWidgetItem(str(log.algorithm_id)))
            self.table_widget.setItem(row, 7, QTableWidgetItem(str(log.bytes)))


        self.table_widget.resizeColumnsToContents()
        self.table_widget.resizeRowsToContents()



    def populate_comboboxes(self):
        frameworks = getFrameworks()
        self.framework_combo.addItems(sorted(list(frameworks)))
        self.framework_combo.currentIndexChanged.connect(self.update_algorithm_combo)
        self.update_algorithm_combo(0)
        self.update_mode_combo(0)

    def update_mode_combo(self, index):
        self.mode_combo.clear()
        framework = self.framework_combo.currentText()
        algorithm_name = self.algorithm_combo.currentText()
        modes = getAlgorithmModes(framework, algorithm_name)
        self.mode_combo.addItems(sorted(modes))

    def update_algorithm_combo(self, index):
        self.algorithm_combo.clear()
        framework = self.framework_combo.currentText()
        algorithms = getAlgorithmByFramework(framework)
        algorithm_names = set(map(lambda x: x.name, algorithms))

        self.algorithm_combo.addItems(sorted(algorithm_names))
        self.algorithm_combo.currentIndexChanged.connect(self.update_key_combo)
        self.update_key_combo(0)
        self.algorithm_combo.currentIndexChanged.connect(self.update_mode_combo)

    def update_key_combo(self, index):
        self.key_length_combo.clear()
        framework = self.framework_combo.currentText()
        algorithm_name = self.algorithm_combo.currentText()
        key_lengths = getAlgorithmKeysLenghts(framework, algorithm_name)
        key_lengths = sorted(map(int, key_lengths))
        key_lengths = list(map(str, key_lengths))
        self.key_length_combo.addItems(key_lengths)



class Window(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Python")
        self.setGeometry(100, 100, 600, 400)
        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)
        self.UiComponents()
        self.show()

    def UiComponents(self):
        main_page = QWidget()
        layout = QHBoxLayout()

        encode_layout = QVBoxLayout()
        encode_layout.setAlignment(Qt.AlignCenter)
        encode_layout.setContentsMargins(0, 80, 0, 0)

        encode_button = QPushButton(self)
        pixmap_encode = QPixmap(
            "../assets/encode.png")
        encode_button.setIcon(QIcon(pixmap_encode))
        encode_button.setIconSize(pixmap_encode.size())
        encode_button.setFixedSize(100, 100)
        encode_layout.addWidget(encode_button)

        encode_text_label = QLabel("Encode", self)
        encode_text_label.setAlignment(Qt.AlignCenter)
        encode_layout.addWidget(encode_text_label)
        encode_layout.addStretch()

        layout.addLayout(encode_layout)

        decode_layout = QVBoxLayout()
        decode_layout.setAlignment(Qt.AlignCenter)
        decode_layout.setContentsMargins(0, 80, 0, 0)

        decode_button = QPushButton(self)
        pixmap_decode = QPixmap(
            "../assets/decode.png")
        decode_button.setIcon(QIcon(pixmap_decode))
        decode_button.setIconSize(pixmap_decode.size())
        decode_button.setFixedSize(100, 100)
        decode_layout.addWidget(decode_button)

        decode_text_label = QLabel("Decode", self)
        decode_text_label.setAlignment(Qt.AlignCenter)
        decode_layout.addWidget(decode_text_label)
        decode_layout.addStretch()

        layout.addLayout(decode_layout)

        show_db_layout = QVBoxLayout()
        show_db_layout.setAlignment(Qt.AlignCenter)
        show_db_layout.setContentsMargins(0, 80, 0, 0)

        performances_button = QPushButton(self)
        # pixmap_encode = QPixmap(
        #     "../assets/encode.png")
        # show_db_button.setIcon(QIcon(pixmap_encode))
        performances_button.setIconSize(pixmap_encode.size())
        performances_button.setFixedSize(100, 100)
        show_db_layout.addWidget(performances_button)

        show_db_text_label = QLabel("Performances", self)
        show_db_text_label.setAlignment(Qt.AlignCenter)
        show_db_layout.addWidget(show_db_text_label)
        show_db_layout.addStretch()
        pixmap_perf = QPixmap(
            "../assets/performance.png")
        performances_button.setIcon(QIcon(pixmap_perf))
        performances_button.setIconSize(pixmap_encode.size())
        performances_button.setFixedSize(100, 100)
        layout.addLayout(show_db_layout)

        encode_button.clicked.connect(self.show_encode_page)
        decode_button.clicked.connect(self.show_decode_page)

        performances_button.clicked.connect(self.show_performances_page)

        main_page.setLayout(layout)

        self.stacked_widget.addWidget(main_page)

    def show_encode_page(self):
        encode_page = EncodePage(self)
        self.stacked_widget.addWidget(encode_page)
        self.stacked_widget.setCurrentWidget(encode_page)
        encode_page.algorithm_combo.currentIndexChanged.connect(self.update_selected_algorithm)

    def update_selected_algorithm(self, index):
        encode_page = self.stacked_widget.currentWidget()
        encode_page.selected_algorithm = encode_page.algorithm_combo.currentText()

    def show_decode_page(self):
        decode_page = DecodePage(self)
        self.stacked_widget.addWidget(decode_page)
        self.stacked_widget.setCurrentWidget(decode_page)

    def show_performances_page(self):
        performances_page = PerformancesPage(self)
        self.stacked_widget.addWidget(performances_page)
        self.stacked_widget.setCurrentWidget(performances_page)

    def back_to_main(self):
        self.stacked_widget.setCurrentIndex(0)


App = QApplication(sys.argv)
window = Window()
sys.exit(App.exec_())
