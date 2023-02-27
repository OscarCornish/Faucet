
"""
get_socket()
Return a raw socket, wrapped into an `IOStream`
"""

const SIOCSIFNAME = Culong(0x8923)
const AF_PACKET = Cushort(3)
const ETH_ALEN = Cuchar(6)
const ETH_P_IP = 0x0800
const ARPHRD_ETHER = Cushort(1)


function get_socket()::IOStream
    #fd = ccall(:socket, Cint, (Cint, Cint, Cint), AF_PACKET, SOCK_RAW, hton(IPPROTO_RAW))
    fd = ccall(:socket, Cint, (Cint, Cint, Cint), Int32(17), Int32(3), 0xff00)
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
    ret = ccall(:if_nametoindex, Cuint, (Cstring,), name)
    if ret == 0
        @error "Failed to get interface index" errno=Base.Libc.errno()
    end
    return ret
end