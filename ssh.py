#! /usr/bin/env python

import paramiko
import time
import sys


class ssh:
    client = None


    def __init__(self, address, username, password, numTries=60):
        i = 0
        while True:
            print("Trying to connect to %s (%i/%d)" % (address, i+1, numTries))

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
                time.sleep(10)
                # If we could not connect within time limit
                i += 1
                if i == numTries:
                    print("Could not connect to %s. Giving up" % address)
                    raise

    def sendCommand(self, command, showoutput=False):
        if self.client:
            all_stdout = ""
            stdin, stdout, stderr = self.client.exec_command(command)
            while not stdout.channel.exit_status_ready():
                # Print data when available
                if stdout.channel.recv_ready():
                    all_stdout = stdout.channel.recv(1024)
                    if showoutput:
                        sys.stdout.write(all_stdout)
                        sys.stdout.flush()
                    prevdata = b"1"
                    while prevdata:
                        prevdata = stdout.channel.recv(1024)
                        if showoutput:
                            sys.stdout.write(prevdata)
                            sys.stdout.flush()
                        all_stdout += prevdata

            rc = stdout.channel.recv_exit_status()
            return rc, all_stdout
        else:
            print("Connection not opened.")
