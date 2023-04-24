#=

    Headers.jl

=#

# C-Related constants
const PCAP_ERRBUF_SIZE  = 256
const ETHERTYPE_IP      = 0x0800
const IPPROTO_TCP       = 0x06
const IPPROTO_UDP       = 0x11
const ETHERTYPE_ARP     = 0x0806

const SOCK_RAW          = 17
const ETH_P_ALL         = 0x0003

const TCP_ACK           = 0x0010
const TCP_SYN           = 0x0002
const TCP_SYN_ACK       = 0x0012
const TCP_PSH_ACK       = 0x0018

#=

Generic types

=#

abstract type Header end

# TODO: Don't have this as mutable, it is slower than a generic struct
#        but not just making a new struct each time thats also slow...
mutable struct Layer{T<:Header}
    layer::Layer_type
    header::T
    payload::Union{Layer, Vector{UInt8}, Missing}
end

mutable struct Pcap end

struct Timeval
    seconds::Clong
    ms::Clong
end

struct Capture_header
    timestamp::Timeval
    capture_length::Int32
    length::Int32
end

# Protocol header definitions, taken from relevant header files

struct ARP_header <: Header
    hardware_type::UInt16
    protocol_type::UInt16
    hardware_length::UInt8
    protocol_length::UInt8
    opcode::UInt16
    sender_mac::NTuple{6, UInt8}
    sender_ip::NTuple{4, UInt8}
    target_mac::NTuple{6, UInt8}
    target_ip::NTuple{4, UInt8}
    function ARP_header(p::Ptr{UInt8})::ARP_header
        return unsafe_load(Ptr{ARP_header}(p))
    end
end

getoffset(::ARP_header)::Int64 = sizeof(ARP_header)
getprotocol(::ARP_header)::UInt8 = 0x0

struct Ethernet_header <: Header
    destination::NTuple{6, UInt8}
    source::NTuple{6, UInt8}
    protocol::UInt16
    function Ethernet_header(p::Ptr{UInt8})::Ethernet_header
        return unsafe_load(Ptr{Ethernet_header}(p))
    end
end

getoffset(::Ethernet_header)::Int64         = sizeof(Ethernet_header)
getprotocol(hdr::Ethernet_header)::UInt16   = ntoh(hdr.protocol)

struct Packet
    cap_header::Capture_header
    payload::Layer{Ethernet_header}
end

# First read base header, then we can deal with options etc.
struct _IPv4_header
    version_ihl::UInt8 # 4 -> version, 4 -> IHL
    tos::UInt8 # Type of service + priority
    tot_len::UInt16 # Total IPv4 length
    id::UInt16 # identification
    frag_off::UInt16 # Fragmented offset
    ttl::UInt8
    protocol::UInt8
    check::UInt16 # Header checksum
    saddr::UInt32
    daddr::UInt32
    function _IPv4_header(p::Ptr{UInt8})::_IPv4_header
        return unsafe_load(Ptr{_IPv4_header}(p))
    end
end

Base.ntoh(x::UInt8)::UInt8 = x
byte_to_nibbles(x::UInt8)::NTuple{2, UInt8} = (x & 0x0f, (x & 0xf0) >> 4)

struct IPv4_header <: Header
    version::UInt8
    ihl::UInt8
    tos::UInt8
    tot_len::UInt16
    id::UInt16
    frag_off::UInt16
    ttl::UInt8
    protocol::UInt8
    check::UInt16
    saddr::UInt32
    daddr::UInt32
    options::UInt32
    function IPv4_header(p::Ptr{UInt8})::IPv4_header
        _ip = _IPv4_header(p)
        version, ihl = byte_to_nibbles(ntoh(_ip.version_ihl)) # Version + IHL
        options_offset = p + sizeof(_IPv4_header)
        options_size = ihl*4 - sizeof(_IPv4_header)
        options = options_size > 0 ? Base.pointerref(options_offset, 1, options_size) : 0
        return new(
            ihl, version, # These two may be flipped depending on byte order
            ntoh(_ip.tos), ntoh(_ip.tot_len), ntoh(_ip.id),
            ntoh(_ip.frag_off), ntoh(_ip.ttl), ntoh(_ip.protocol),
            ntoh(_ip.check), ntoh(_ip.saddr), ntoh(_ip.daddr),
            ntoh(options)
        )
    end
end    

getoffset(hdr::IPv4_header)::Int64      = hdr.ihl * 4
getprotocol(hdr::IPv4_header)::UInt8    = hdr.protocol

struct _TCP_header
    sport::UInt16
    dport::UInt16
    seq::UInt32
    ack_num::UInt32
    flags::UInt16
    win_size::UInt16
    check::UInt16
    urg_ptr::UInt16
    function _TCP_header(p::Ptr{UInt8})::_TCP_header
        return unsafe_load(Ptr{_TCP_header}(p))
    end
end

struct TCP_header <: Header
    sport::UInt16
    dport::UInt16
    seq::UInt32
    ack_num::UInt32
    hdr_len::UInt8
    reserved::UInt8
    urg::Bool
    ack::Bool
    psh::Bool
    rst::Bool
    syn::Bool
    fin::Bool
    win_size::UInt16
    check::UInt16
    urg_ptr::UInt16
    #options::NTuple{10, UInt32}
    function TCP_header(p::Ptr{UInt8})::TCP_header
        _tcp = _TCP_header(p)
        flags = ntoh(_tcp.flags)
        header_length   =  (flags & 0b1111000000000000) >> 12
        reserved   = UInt8((flags & 0b0000111111000000) >> 6)
        urg             = ((flags & 0b0000000000100000) >> 5) == 0x1
        ack             = ((flags & 0b0000000000010000) >> 4) == 0x1
        psh             = ((flags & 0b0000000000001000) >> 3) == 0x1
        rst             = ((flags & 0b0000000000000100) >> 2) == 0x1
        syn             = ((flags & 0b0000000000000010) >> 1) == 0x1
        fin             = ((flags & 0b0000000000000001)     ) == 0x1
        #options_offset = p + sizeof(_TCP_header)
        #options_size = header_length*4 - sizeof(_TCP_header)
        #options = options_size > 0 ? Base.pointerref(options_offset, 1, options_size) : zeros(UInt32, 10)
        # Go from network byte order to host byte order (excluding flags as we already changed them)
        return new(
            ntoh(_tcp.sport), ntoh(_tcp.dport), ntoh(_tcp.seq), ntoh(_tcp.ack_num),
            header_length, reserved, urg, ack, psh, rst, syn, fin, 
            ntoh(_tcp.win_size), ntoh(_tcp.check), ntoh(_tcp.urg_ptr)#, options
        )
    end
end

getoffset(hdr::TCP_header)::Int64           = hdr.hdr_len * 4
getprotocol(lyr::Layer{TCP_header})::UInt64 = lyr.payload[1:min(end, 4)] # No protocol field...

struct UDP_header <: Header
    sport::UInt16
    dport::UInt16
    len::UInt16
    check::UInt16
    function UDP_header(p::Ptr{UInt8})::UDP_header
        return unsafe_load(Ptr{UDP_header}(p))
    end
end

getoffset(::UDP_header)::Int64                  = sizeof(UDP_header)
getprotocol(lyr::Layer{UDP_header})::Unsigned   = lyr.payload[1:min(length(lyr.payload), 4)]

# Default layer -> header call
getoffset(lyr::Layer{<:Header})::Int64          = getoffset(lyr.header)
getprotocol(lyr::Layer{<:Header})::Unsigned     = getprotocol(lyr.header)

#=

    Header tree

=#

struct Node
    type::Type{<:Header}
    id::Unsigned
    children::Vector{Node}
end

# Transport - 4

HEADER_UDP = Node(
    UDP_header,
    IPPROTO_UDP,
    []
)

HEADER_TCP = Node(
    TCP_header,
    IPPROTO_TCP,
    []
)

# Network - 3

HEADER_IPv4 = Node(
    IPv4_header,
    ETHERTYPE_IP,
    [HEADER_TCP, HEADER_UDP]
)

HEADER_ARP = Node(
    ARP_header,
    ETHERTYPE_ARP,
    []
)

# Link - 2

HEADER_Ethernet = Node(
    Ethernet_header,
    0x00,
    [HEADER_IPv4, HEADER_ARP]
)
