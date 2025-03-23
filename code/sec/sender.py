import os
import socket
import time

def udp_sender():
    host = os.getenv('INSECURENET_HOST_IP')
    port = 8888
    message = "Hello, InSecureNet!"

    if not host:
        print("SECURENET_HOST_IP environment variable is not set.")
        return
    
    rtt_list = [] # List to store round trip times

    try:
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        while True:

            sending_time = time.time() # Sending time

            # Send message to the server
            sock.sendto(message.encode(), (host, port))
            print(f"Message sent to {host}:{port}")

            # Receive response from the server
            response, server = sock.recvfrom(4096)

            receiving_time = time.time()  # Receiving time
            rtt = (receiving_time - sending_time) * 1000  # Round trip time in milliseconds

            print(f"Response from server: {response.decode()}")

            rtt_list.append(rtt)

            # Sleep for 1 second
            time.sleep(1)

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        sock.close()

        with open("rtt_results.txt", "w") as f:
            for rtt in rtt_list:
                f.write(f"{rtt:.3f}\n")

if __name__ == "__main__":
    udp_sender()