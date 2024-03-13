import socket
import os

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5555
BUFFER_SIZE = 4096
SEPARATOR = '<SEPARATOR>'
SERVER_FOLDER = "server_folder"


def receive_file(conn):
    received = conn.recv(BUFFER_SIZE).decode()
    print(f"[RECV] Receiving the file data: {received}")

    if SEPARATOR in received:
        parts = received.split(SEPARATOR)
        filename = parts[1]  # Fetching the filename
        filesize = int(parts[2])  # Fetching the filesize
        download_path = os.path.join(SERVER_FOLDER, filename)

        with open(download_path, 'wb') as f:
            while filesize > 0:
                bytes_read = conn.recv(BUFFER_SIZE)
                f.write(bytes_read)
                filesize -= len(bytes_read)

        print(f"File '{filename}' received.")
    else:
        print("Invalid data format received.")

        def receive_file(conn):
            received = conn.recv(BUFFER_SIZE).decode()
            print(f"[RECV] Receiving the file data")
            filename, filesize = received.split(SEPARATOR)
            filename = os.path.basename(filename)
            filesize = int(filesize)
            # Dosyanın kaydedileceği konumu belirle
            download_path = os.path.join(SERVER_FOLDER, filename)
            with open(filename, 'wb') as f:
                while filesize > 0:
                    bytes_read = conn.recv(BUFFER_SIZE)
                    f.write(bytes_read)
                    filesize -= len(bytes_read)

            print(f"{filename} received.")


def send_file(conn, filename):
    with open(filename, 'rb') as f:
        conn.send(f"{filename}{SEPARATOR}{os.path.getsize(filename)}".encode())
        while True:
            bytes_read = f.read(BUFFER_SIZE)
            if not bytes_read:
                break
            conn.sendall(bytes_read)

def list_files():
    files = "\n".join(os.listdir())
    return files if files else "Directory is empty."

def create_folder(folder_name):
    try:
        os.mkdir(folder_name)
        return f"Folder '{folder_name}' created."
    except FileExistsError:
        return f"Folder '{folder_name}' already exists."

def delete_file_or_folder(file_name):
    if os.path.exists(file_name):
        if os.path.isfile(file_name):
            os.remove(file_name)
            return f"File '{file_name}' deleted."
        elif os.path.isdir(file_name):
            os.rmdir(file_name)
            return f"Folder '{file_name}' deleted."
    return f"'{file_name}' does not exist."

def move_file_or_folder(file_name, dest_folder):
    try:
        os.rename(file_name, os.path.join(dest_folder, file_name))
        return f"'{file_name}' moved to '{dest_folder}'."
    except FileNotFoundError:
        return f"'{file_name}' not found."
    except FileExistsError:
        return f"'{file_name}' already exists in '{dest_folder}'."

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((SERVER_HOST, SERVER_PORT))
    s.listen(5)
    print(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")

    while True:
        conn, addr = s.accept()
        print(f"[+] {addr} is connected.")
        try:
            data = conn.recv(BUFFER_SIZE).decode()
            if not data:
                break

            if data == "LIST":
                files = list_files()
                conn.send(files.encode())

            elif data.startswith("CREATE_FOLDER"):
                folder_name = data.split(SEPARATOR)[1]
                response = create_folder(folder_name)
                conn.send(response.encode())

            elif data.startswith("DELETE"):
                file_name = data.split(SEPARATOR)[1]
                response = delete_file_or_folder(file_name)
                conn.send(response.encode())

            elif data.startswith("MOVE"):
                parts = data.split(SEPARATOR)
                file_name = parts[1]
                dest_folder = parts[2]
                response = move_file_or_folder(file_name, dest_folder)
                conn.send(response.encode())

            elif data.startswith("SEND"):
                filename = data.split(SEPARATOR)[1]
                receive_file(conn)

            elif data.startswith("RECEIVE"):
                filename = data.split(SEPARATOR)[1]
                send_file(conn, filename)

        except Exception as e:
            print(f"[-] Error: {e}")
            break

    s.close()

if __name__ == "__main__":
    main()