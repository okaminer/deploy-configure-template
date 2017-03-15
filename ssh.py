#! /usr/bin/env python

import paramiko
import time

class ssh:
    client = None
 
 
    def __init__(self, address, username, password):
        while True:
            i = 0
            print "Trying to connect to %s (%i/30)" % (address, i)

            try:
                print("Connecting to server.")
                self.client = paramiko.SSHClient()
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.client.connect(address, username=username, password=password, look_for_keys=False)
                print("Connected to %s" % address)
                break
            except paramiko.AuthenticationException:
                print("Authentication failed when connecting to %s" % address)
                sys.exit(1)
            except:
                print("Could not SSH to %s, waiting for it to start" % address)
                i += 1
                time.sleep(5)

            # If we could not connect within time limit
            if i == 30:
                print("Could not connect to %s. Giving up" % address)
                sys.exit(1)


 
    def sendCommand(self, command):
        if(self.client):
            stdin, stdout, stderr = self.client.exec_command(command)
            while not stdout.channel.exit_status_ready():
                # Print data when available
                if stdout.channel.recv_ready():
                    alldata = stdout.channel.recv(1024)
                    prevdata = b"1"
                    while prevdata:
                        prevdata = stdout.channel.recv(1024)
                        alldata += prevdata

                    return(alldata)
        else:
            print("Connection not opened.")

