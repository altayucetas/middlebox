import os
import time
import socket
from scapy.all import IP, TCP, send

def xor_encrypt(msg, key):
    out = []
    for i in range(len(msg)):
        c = msg[i]
        k = key[i % len(key)]
        out.append(chr(ord(c) ^ ord(k)))  # XOR encryption of character with key
    return out

def tcp_sender(message, key, dst_port=8888, udp_port=9999):
    host = os.getenv('INSECURENET_HOST_IP')  # Destination IP from environment variable
    times = []  # List to store round trip times

    if not host:
        print("SECURENET_HOST_IP environment variable is not set.")  # Error if IP is missing
        return

    try:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create UDP socket
        udp.bind(('', udp_port))  # Bind UDP socket to local port

        while True:
            start = time.time()  # Sending time

            head = f"LEN:{len(message)}"  # Create header with message length
            opts = [(76, head.encode())]  # TCP option for header
            pkt = IP(dst=host)/TCP(dport=dst_port, flags="S", options=opts)  # TCP packet with header
            send(pkt, verbose=False)

            crypted = xor_encrypt(message, key)  # Encrypt the message
            for ch in crypted:
                opts = [(76, ch.encode())]
                pkt = IP(dst=host)/TCP(dport=dst_port, flags="S", options=opts)
                send(pkt, verbose=False)

            print(f"Message sent to {host}:{dst_port}")  # Confirm message sent

            resp, addr = udp.recvfrom(4096)  # Wait for response from receiver
            end = time.time()  # Receiving time
            print(f"Response from server: {resp.decode()}")  # Print response

            rtt = (end - start) * 1000  # Round trip time in milliseconds
            times.append(rtt)

            time.sleep(1)

    except Exception as e:
        print(f"An error occurred: {e}")  # Print error
    finally:
        udp.close()
        with open("rtt_results.txt", "w") as f:
            for t in times:
                f.write(f"{t:.3f}\n")  # Write RTTs to file

if __name__ == "__main__":
    msg = "Hi, Insec!" # Message to send
    key = "altay" # XOR key
    dst_port = 8888 # Target port on receiver
    udp_port = 9999 # Local UDP port to receive reply
    tcp_sender(msg, key, dst_port, udp_port)
