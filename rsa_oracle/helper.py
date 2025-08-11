import socket
import re


class Downloader:
    # -- Configuration --

    TIMEOUT = 5  # seconds

    def __init__(self, port, host="titan.picoctf.net"):
        self.HOST = host
        self.PORT = port

    def recv_until(self, s, delimiter):
        """
        Receives data from the socket `s` until the `delimiter` string is found.
        This is crucial for waiting for the server's prompts.
        """
        # We work with bytes, so we encode the string delimiter
        delimiter_bytes = delimiter.encode("utf-8")
        buffer = b""
        while delimiter_bytes not in buffer:
            try:
                # Receive data in chunks
                chunk = s.recv(4096)
                if not chunk:
                    # The server closed the connection
                    raise ConnectionError("Socket connection closed by the server.")
                buffer += chunk
            except socket.timeout:
                raise TimeoutError(f"Timed out waiting for delimiter: {delimiter}")

        # Decode the received bytes into a string for easy processing
        output_str = buffer.decode("utf-8")
        # print(f"[<] Received:\n---\n{output_str.strip()}\n---")
        return output_str

    def send_all(self, s, data):
        """
        Sends data to the socket `s` and logs it for debugging.
        Appends a newline character, as most command-line services are line-buffered.
        """
        # We work with bytes, so we encode the string data
        data_with_newline = data + "\n"
        # print(f"[>] Sending: {data_with_newline.strip()}")
        s.sendall(data_with_newline.encode("utf-8"))

    def get_encryption(self, plaintext, version="text"):
        """
        Connects to the oracle, sends the plaintext for encryption, and returns the ciphertext.
        """
        # print(f"\n[+] --- Starting Encryption for '{plaintext}' ---")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(self.TIMEOUT)
            try:
                s.connect((self.HOST, self.PORT))
                self.recv_until(s, "E --> encrypt D --> decrypt. \n")
                self.send_all(s, "e")
                self.recv_until(s, "enter text to encrypt (encoded length must be less than keysize): ")
                self.send_all(s, plaintext)
                response = self.recv_until(s, "E --> encrypt D --> decrypt. \n")

                match = re.search(r"ciphertext \(m \^ e mod n\) (\d+)", response)
                if match:
                    ciphertext = match.group(1)
                    # return response
                    if version == "hex":
                        return re.sub("^.+Hex m: ", "", response.split("\n")[2])
                    if version == "text":
                        return ciphertext
                    else:
                        return response
                else:
                    raise ValueError("Could not parse ciphertext from the response.")

            except (ConnectionRefusedError, socket.gaierror, TimeoutError, ConnectionError, ValueError):
                # print(f"[!] Encryption failed: {e}")
                return None

    def get_decryption(self, ciphertext, version="hex"):
        """
        Connects to the oracle, sends the ciphertext for decryption, and returns the plaintext.
        """
        # print("\n[+] --- Starting Decryption ---")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(self.TIMEOUT)
            try:
                s.connect((self.HOST, self.PORT))
                self.recv_until(s, "E --> encrypt D --> decrypt. \n")
                self.send_all(s, "d")  # Choose 'd' for decrypt
                self.recv_until(s, "Enter text to decrypt: ")  # Wait for the decrypt prompt
                self.send_all(s, ciphertext)  # Send the big number
                response = self.recv_until(s, "what should we do for you? \n")
                # return response
                if version == "hex":
                    return re.sub("^.+n\): ", "", response.split("\n")[0])
                elif version == "text":
                    return re.sub("^.+text: ", "", response.split("\n")[1])
                else:
                    return response
                # The final plaintext is on the line "decrypted ciphertext: ..."
                # match = re.search(r"decrypted ciphertext: (.*)", response)
                # if match:
                #     plaintext = match.group(1).strip()
                #     print("[✅] Decryption successful.")
                #     return response
                # else:
                #     raise ValueError("Could not parse plaintext from the response.")

            except ConnectionError:
                print("OI! DISCONNECTED???")
                return None
            except (ConnectionRefusedError, socket.gaierror, TimeoutError, ValueError):
                # print(f"[!] Decryption failed: {e}")
                return None
