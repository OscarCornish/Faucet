#=

    Define constants

=#

@debug "constants: Loading..."

# Program related constants
const ENVIRONMENT_QUEUE_SIZE = 150
const MINIMUM_CHANNEL_SIZE   = 4
const PACKET_SEND_RATE       = 0.01 # We want to send packets at 1% of the rate of network traffic

# C-Related constants
const PCAP_ERRBUF_SIZE  = 256
const ETHERTYPE_IP      = 0x0800
const IPPROTO_TCP       = 0x06
const IPPROTO_UDP       = 0x11

const SOCK_RAW          = 17
const AF_PACKET         = 3
const ETH_P_ALL         = 0x0003

const TCP_ACK           = 0x0010
const TCP_SYN           = 0x0002
const TCP_SYN_ACK       = 0x0012
const TCP_PSH_ACK       = 0x0018

@debug "constants: Defined constants."
