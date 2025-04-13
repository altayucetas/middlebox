import socket, os
from scapy.all import sniff, TCP, IP

def xor_decrypt(msg_list, key):
    result = []
    for i in range(len(msg_list)):
        m = msg_list[i]
        k = key[i % len(key)]
        result.append(chr(ord(m) ^ ord(k)))  # XOR decryption of character
    return ''.join(result)

def start_udp_listener(xor_key, reply_msg, dst_port=8888, udp_send_port=9999):
    print(f"UDP listener started on TCP port {dst_port}")  # Show port info

    msg_len = None  # Expected length of message
    msg_chars = []  # Collected encrypted characters
    opt_id = 76  # TCP option kind for incoming data

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # Create UDP socket

    def get_data(pkt):
        if TCP in pkt and pkt[TCP].options:
            for o in pkt[TCP].options:
                if isinstance(o, tuple) and o[0] == opt_id:
                    return o[1].decode(errors='ignore')  # Extract covert data
        return None

    def process(pkt):
        nonlocal msg_len, msg_chars
        if TCP in pkt and pkt[TCP].dport == dst_port:  # Check destination TCP port
            src = pkt[IP].src if pkt.haslayer(IP) else "0.0.0.0"  # Source IP
            addr = (src, udp_send_port)  # Address to send reply
            d = get_data(pkt)  # Extract data from TCP option
            if not d:
                return

            if msg_len is None and d.startswith("LEN:"):  # If it's header packet
                try:
                    msg_len = int(d.split(":")[1])  # Parse message length
                except:
                    pass
                return

            if msg_len is not None:
                msg_chars.append(d)  # Add encrypted character
                if len(msg_chars) == msg_len:  # If full message received
                    clear = xor_decrypt(msg_chars, xor_key)  # Decrypt the message
                    print(f"Received {len(clear.encode())} bytes from {addr}")  # Show size
                    print(clear)  # Print decrypted message
                    r = reply_msg.encode()  # Encode reply
                    if r:
                        s = udp.sendto(r, addr)  # Send reply back via UDP
                        print(f"Sent {s} bytes back to {addr}")  # Confirm reply
                    msg_len = None  # Reset for next message
                    msg_chars.clear()

    sniff(filter=f"tcp port {dst_port}", prn=process, store=0)  # Start sniffing TCP packets

if __name__ == "__main__":
    reply = "Ack!"  # Response to be sent back
    key = "altay"  # XOR key
    dst_port = 8888  # TCP port to listen
    udp_reply_port = 9999  # UDP port to send back to
    start_udp_listener(key, reply, dst_port, udp_reply_port)
