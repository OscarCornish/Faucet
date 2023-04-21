
"""
get_socket()
Return a raw socket, wrapped into an `IOStream`
"""

const SIOCSIFNAME = Culong(0x8923)
const AF_PACKET = Cushort(3)
const ETH_ALEN = Cuchar(6)
const ETH_P_IP = 0x0800
const ARPHRD_ETHER = Cushort(1)


function get_socket(domain::Cint, type::Cint, protocol::Cint)::IOStream
    fd = ccall(:socket, Cint, (Cint, Cint, Cint), domain, type, protocol)
    if fd == -1
        @error "Failed to open socket" errno=Base.Libc.errno()
    end
    return fdio(fd)
end

struct Sockaddr_ll
    sll_family::Cushort
    sll_protocol::Cushort
    sll_ifindex::Cint
    sll_hatype::Cushort
    sll_pkttype::Cuchar
    sll_halen::Cuchar
    sll_addr::NTuple{6, Cuchar}
    function Sockaddr_ll(;
        sll_family::Cushort=hton(AF_PACKET),
        sll_protocol::Cushort=hton(ETH_P_IP),
        sll_ifindex::Cint,
        sll_hatype::Cushort=hton(ARPHRD_ETHER),
        sll_pkttype::Cuchar=Cuchar(0),
        sll_halen::Cuchar=ETH_ALEN,
        sll_addr::NTuple{6, Cuchar}
    )
        new(sll_family, sll_protocol, sll_ifindex, sll_hatype, sll_pkttype, sll_halen, sll_addr)
    end
end

function sendto(sockfd::Integer, packet::Vector{UInt8}, interface_id::Integer)::Cint
    sockfd = sockfd == Cint(sockfd) ? Cint(sockfd) : error("sockfd size is unsupported")
    interface_id = interface_id == Cint(interface_id) ? Cint(interface_id) : error("interface_id size is unsupported")
    # Dest addr in packet at know offset
    destination_addr = NTuple{6, Cuchar}(packet[7:12])
    # Create sockaddr_ll
    sockaddr_ll = Sockaddr_ll(sll_ifindex=interface_id, sll_addr=destination_addr)
    # Send packet
    bytes = ccall(:sendto, Cint, (Cint, Ptr{UInt8}, Csize_t, Cint, Ptr{Sockaddr_ll}, Cint), sockfd, packet, length(packet), 0, Ref(sockaddr_ll), sizeof(sockaddr_ll))
    if bytes == -1
        @error "Failed to send packet" errno=Base.Libc.errno()
    end
    return bytes
end

sendto(sockfd::Integer, packet::Vector{UInt8}, interface_name::String)::Cint = sendto(sockfd, packet, if_nametoindex(interface_name))
sendto(sock::IOStream, packet::Vector{UInt8}, interface_name::Union{String, Cint})::Cint = sendto(fd(sock), packet, interface_name)

function ioctl(sockfd::Cint, request::Culong, value::Ref{UInt8})::Nothing
    ret = ccall(:ioctl, Cint, (Cint, Cint, Ref{UInt8}), sockfd, request, value)
    if ret == -1
        @error "Failed to set socket options" errno=Base.Libc.errno()
    end
    return nothing
end

function if_nametoindex(name::String)::Cuint
    ifface_idx = ccall(:if_nametoindex, Cuint, (Cstring,), name)
    if ifface_idx == 0
        @error "Failed to get interface index" errno=Base.Libc.errno()
    end
    @assert if_indextoname(ifface_idx) != name "Mismatch in interface id and name, got '$(if_indextoname(ifface_idx))' instead of '$name' ($ifface_idx)"
    return ifface_idx
end

function if_indextoname(index::Cuint)::String
    name = Vector{UInt8}(undef, 16)
    ret = ccall(:if_indextoname, Ptr{UInt8}, (Cuint, Ptr{UInt8}), index, name)
    if ret == C_NULL
        @error "Failed to get interface name" errno=Base.Libc.errno()
    end
    return String(name)
end

"""
    await_arp_beacon(source_ip::IPAddr, timeout::Int)::Union{Nothing, UInt8}

Await an arp beacon from the source address, return nothing if timeout is reached, otherwise return the data
"""
await_arp_beacon(source_ip::String, timeout::Int)::Union{Nothing, UInt8} = await_arp_beacon(IPv4Addr(source_ip), timeout)

# Sequence of bytes for an ARP packet, starting from ethertype ending at at the opcode (0x0001 for request)
const ARP_SEQUENCE        = [0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01]
const ARP_SEQUENCE_SLICE  = 13:22
const ARP_SRC_SLICE       = 29:32
const ARP_DEST_SLICE      = 39:42

function await_arp_beacon(ip::IPAddr, timeout::Int64=5)
    socket = get_socket(Int32(17), Int32(3), Int32(0x0300))
    start = time_ns()
    while (time_ns() - start) < timeout * 1e9
        raw = read(socket)
        if length(raw) >= 42
            if raw[ARP_SEQUENCE_SLICE] == ARP_SEQUENCE
                if raw[ARP_SRC_SLICE] == _to_bytes(ip.host)
                    return raw[ARP_DEST_SLICE][4]
                end
            end
        end
    end
end