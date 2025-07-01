from r4ghidra import R4GhidraServer, R4GhidraState

from ghidra.program.flatapi import FlatProgramAPI

import os
import time

R4GhidraState.api = FlatProgramAPI(currentProgram)
R4GhidraState.r2Seek = R4GhidraState.api.toAddr(0)

port=9191
if "R4GHIDRA_PORT" in os.environ:
    port=int(os.environ["R4GHIDRA_PORT"])
elif "R2WEB_PORT" in os.environ:  # Keep old variable for backwards compatibility
    port=int(os.environ["R2WEB_PORT"])

print("R4Ghidra Starting server on port %d" % (port))
R4GhidraServer.start(port)

# TODO We'll need a HTTP server like Jetty to properly wait() for server stop
while True:
    user_input=raw_input("R4Ghidra E(x)it? ")
    if user_input == 'x':
        R4GhidraServer.stop()
        break

