#!/bin/bash

# Kill every local node. The old spelling is matched for one release cycle:
# a `quantus-node` left running from before the rename holds 30333 and 9944
# against the new binary, and the failure it causes names neither.
pkill -f 'q(nero|uantus)-node'
