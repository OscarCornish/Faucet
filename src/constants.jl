#=

    Define constants for the program
        (True constants are defined in files where they are used)

=#

# Program related constants
const ENVIRONMENT_QUEUE_SIZE = 150
const MINIMUM_CHANNEL_SIZE   = 4

# We want to send packets at 1% of the rate of network traffic
const PACKET_SEND_RATE       = 0.01
