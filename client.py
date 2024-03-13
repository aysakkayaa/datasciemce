import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.primitives import padding
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5555
BUFFER_SIZE = 4096
SEPARATOR = '<SEPARATOR>'
CLENT_FOLDER = "client_folder"

def send_file(filepath):
    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER_HOST, SERVER_PORT))
        # Send the file path and its size, separated by the defined SEPARATOR
        s.send(f"SEND{SEPARATOR}{filename}{SEPARATOR}{filesize}".encode())
        # Send the file contents
        with open(filepath, 'rb') as f:
            while True:
                bytes_read = f.read(BUFFER_SIZE)
                if not bytes_read:
                    break
                s.sendall(bytes_read)
        print(f"File '{filename}' sent successfully.")

# ... (rest of your code remains unchanged)



def receive_file():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER_HOST, SERVER_PORT))
        s.send("RECEIVE".encode())
        received = s.recv(BUFFER_SIZE).decode()
        filename, filesize = received.split(SEPARATOR)
        filename = os.path.basename(filename)
        filesize = int(filesize)
        with open(filename, 'wb') as f:
            while filesize > 0:
                bytes_read = s.recv(BUFFER_SIZE)
                f.write(bytes_read)
                filesize -= len(bytes_read)
        print(f"File '{filename}' received successfully.")

def send_command(command):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER_HOST, SERVER_PORT))
        s.send(command.encode())
        response = s.recv(BUFFER_SIZE).decode()
        print(response)

def main():
    while True:
        print("\n1. List Files")
        print("2. Create Folder")
        print("3. Delete File or Folder")
        print("4. Move File or Folder")
        print("5. Send File to Server")
        print("6. Receive File from Server")
        print("0. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            send_command("LIST")

        elif choice == "2":
            folder_name = input("Enter folder name to create: ")
            send_command(f"CREATE_FOLDER{SEPARATOR}{folder_name}")

        elif choice == "3":
            file_name = input("Enter file or folder name to delete: ")
            send_command(f"DELETE{SEPARATOR}{file_name}")

        elif choice == "4":
            file_name = input("Enter file or folder name to move: ")
            dest_folder = input("Enter destination folder: ")
            send_command(f"MOVE{SEPARATOR}{file_name}{SEPARATOR}{dest_folder}")

        elif choice == "5":
            def select_file():
                file_path = filedialog.askopenfilename()
                entry_file_path.delete(0, tk.END)
                entry_file_path.insert(0, file_path)

            def encrypt_file():
                file_path = entry_file_path.get()
                algorithm = var_algorithm.get()
                password = entry_password.get()

                backend = default_backend()

                # Key türetiliyor
                salt = os.urandom(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=backend
                )
                key = kdf.derive(password.encode())

                # İv oluşturuluyor
                if algorithm == 'AES':
                    iv = os.urandom(16)  # AES için CFB modunda IV boyutu 16 bayt olmalıdır
                elif algorithm == 'DES' or algorithm == 'Blowfish':
                    iv = os.urandom(8)  # DES ve Blowfish için CFB modunda IV boyutu 8 bayt olmalıdır
                else:
                    raise ValueError("Geçersiz algoritma")

                # Dosya içeriği okunuyor
                with open(file_path, 'rb') as file:
                    plaintext = file.read()

                # Padding yapılıyor
                padder = padding.PKCS7(64).padder()
                padded_plaintext = padder.update(plaintext) + padder.finalize()

                # Şifreleme yapılıyor
                cipher = Cipher(algorithms.Blowfish(key), modes.CFB(iv),
                                backend=backend) if algorithm == 'Blowfish' else \
                    Cipher(algorithms.AES(key) if algorithm == 'AES' else algorithms.TripleDES(key[:24]), modes.CFB(iv),
                           backend=backend)

                encryptor = cipher.encryptor()
                ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

                # Şifreli dosyayı oluştur
                encrypted_file_path = f"{file_path}.enc"
                with open(encrypted_file_path, 'wb') as encrypted_file:
                    encrypted_file.write(salt + iv + ciphertext)

                lbl_status.config(
                    text=f"{file_path} dosyası {algorithm} algoritmasıyla şifrelendi ve {encrypted_file_path} olarak kaydedildi.")

            def decrypt_file():
                encrypted_file_path = entry_file_path.get()
                algorithm = var_algorithm.get()
                password = entry_password.get()

                backend = default_backend()

                # Şifreli dosyayı oku
                with open(encrypted_file_path, 'rb') as file:
                    data = file.read()
                    salt = data[:16]
                    iv = data[16:16 + (16 if algorithm == 'AES' else 8)]  # IV'nin doğru boyutta alınması
                    ciphertext = data[16 + (16 if algorithm == 'AES' else 8):]

                # Key türetiliyor
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                    backend=backend
                )
                key = kdf.derive(password.encode())

                # Şifre çözme
                cipher = Cipher(algorithms.Blowfish(key), modes.CFB(iv),
                                backend=backend) if algorithm == 'Blowfish' else \
                    Cipher(algorithms.AES(key) if algorithm == 'AES' else algorithms.TripleDES(key[:24]), modes.CFB(iv),
                           backend=backend)

                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

                # Unpadding
                unpadder = padding.PKCS7(64).unpadder()
                unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

                # Şifresiz dosyayı oluştur
                decrypted_file_path = encrypted_file_path[:-4]  # .enc uzantısını kaldır
                with open(decrypted_file_path, 'wb') as decrypted_file:
                    decrypted_file.write(unpadded_data)

                lbl_status.config(
                    text=f"{encrypted_file_path} dosyası {algorithm} algoritmasıyla çözüldü ve {decrypted_file_path} olarak kaydedildi.")

            # Tkinter penceresi oluştur
            root = tk.Tk()
            root.title("Dosya Şifreleme Aracı")

            # Dosya seçme düğmesi
            btn_browse = tk.Button(root, text="Dosya Seç", command=select_file)
            btn_browse.pack()

            # Dosya yolu girişi
            entry_file_path = tk.Entry(root, width=50)
            entry_file_path.pack()

            # Algoritma seçimi
            var_algorithm = tk.StringVar()
            var_algorithm.set("AES")

            lbl_algorithm = tk.Label(root, text="Kullanılacak Algoritma:")
            lbl_algorithm.pack()

            rdbtn_aes = tk.Radiobutton(root, text="AES", variable=var_algorithm, value="AES")
            rdbtn_aes.pack()

            rdbtn_des = tk.Radiobutton(root, text="DES", variable=var_algorithm, value="DES")
            rdbtn_des.pack()

            rdbtn_blowfish = tk.Radiobutton(root, text="Blowfish", variable=var_algorithm, value="Blowfish")
            rdbtn_blowfish.pack()

            # Şifre girişi
            lbl_password = tk.Label(root, text="Şifre:")
            lbl_password.pack()

            entry_password = tk.Entry(root, show="*")
            entry_password.pack()

            # Şifrele ve Çöz düğmeleri
            btn_encrypt = tk.Button(root, text="Dosyayı Şifrele", command=encrypt_file)
            btn_encrypt.pack()

            btn_decrypt = tk.Button(root, text="Dosyayı Çöz", command=decrypt_file)
            btn_decrypt.pack()

            # Durum etiketi
            lbl_status = tk.Label(root, text="")
            lbl_status.pack()

            root.mainloop()


        elif choice == "6":
            receive_file()

        elif choice == "0":
            break

        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()