Starting the Sniffer:

Explanation:

    if __name__ == "__main__": is a special Python statement that ensures some code runs only when the script is executed directly, not when it's imported as a module.
    print("Starting network sniffer...") displays a message to indicate that the sniffer is starting.
    sniff(prn=packet_handler, count=10): This line starts the packet capture.
        prn=packet_handler: Specifies that for every packet captured, the packet_handler function should be called.
        count=10000: Captures 10 packets. You can change this number or remove it to capture packets indefinitely.


        Running the Script

    Save the script in a file named network_sniffer.py.
    Open your terminal or command prompt, navigate to the folder where your script is saved, and run the script using:

sudo python3 network_sniffer.py
