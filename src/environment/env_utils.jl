"""
    get_socket(domain, type, protocol)::IOStream
Return a raw socket, wrapped into an `IOStream`
"""
function get_socket(domain::Cint, type::Cint, protocol::Cint)::IOStream
    fd = ccall(:socket, Cint, (Cint, Cint, Cint), domain, type, protocol)
    if fd == -1
        @error "Failed to open socket" errno=Base.Libc.errno()
    end
    return fdio(fd)
end

"""
Link-layer socket address structure
    required for sending packets at the link-layer
    indicates the interface to send the packet to.
"""
struct Sockaddr_ll
    sll_family::Cushort
    sll_protocol::Cushort
    sll_ifindex::Cint
    sll_hatype::Cushort
    sll_pkttype::Cuchar
    sll_halen::Cuchar
    sll_addr::NTuple{6, Cuchar}
    function Sockaddr_ll(;
        sll_family::Cushort=hton(UInt16(AF_PACKET)),
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

"""
    sendto(sockfd, packet, interface_id)::Cint

Send a packet to the interface with the given id.
"""
sendto(sock::IOStream, packet::Vector{UInt8}, interface_name::Union{String, Cint})::Cint = sendto(fd(sock), packet, interface_name)
sendto(sockfd::Integer, packet::Vector{UInt8}, interface_name::String)::Cint = sendto(sockfd, packet, if_nametoindex(interface_name))
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

"""
Get the interface index for the given interface name.
see also: [`if_indextoname`](@ref)
"""
function if_nametoindex(name::String)::Cuint
    ifface_idx = ccall(:if_nametoindex, Cuint, (Cstring,), name)
    if ifface_idx == 0
        @error "Failed to get interface index" errno=Base.Libc.errno()
    end
    @assert if_indextoname(ifface_idx) != name "Mismatch in interface id and name, got '$(if_indextoname(ifface_idx))' instead of '$name' ($ifface_idx)"
    return ifface_idx
end

"""
Get the interface name for the given interface index.
see also: [`if_nametoindex`](@ref)
"""
function if_indextoname(index::Cuint)::String
    name = Vector{UInt8}(undef, 16)
    ret = ccall(:if_indextoname, Ptr{UInt8}, (Cuint, Ptr{UInt8}), index, name)
    if ret == C_NULL
        @error "Failed to get interface name" errno=Base.Libc.errno()
    end
    return String(name)
end

# Sequence of bytes for an ARP packet, starting from ethertype ending at at the opcode (0x0001 for request)
const ARP_SEQUENCE        = [0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01]
# The slice the above sequence is found in
const ARP_SEQUENCE_SLICE  = 13:22
# The slice the source address is found in
const ARP_SRC_SLICE       = 29:32
# The slice the destination address is found in
const ARP_DEST_SLICE      = 39:42

"""
Await an arp beacon from the source address, return nothing if timeout is reached, otherwise return the data
"""
function await_arp_beacon(ip::IPv4Addr, target::UInt8, timeout::Int64=5)
    # Get a fresh socket to listen on
    socket = get_socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)
    heard = Vector{UInt8}()
    @debug "Started listening @" time() timeout
    start = time_ns()
    while (time_ns() - start) < timeout * 1e9
        # Read a packet
        raw = read(socket)
        # Confirm it is more than the mininum size of an ARP packet
        if length(raw) >= 42
            # Check it matches our boilerplate ARP
            if raw[ARP_SEQUENCE_SLICE] == ARP_SEQUENCE
                # Check it is from the source we are looking for
                if raw[ARP_SRC_SLICE] == _to_bytes(ip.host)
                    # Check it is to the target we are looking for
                    if raw[ARP_DEST_SLICE][4] == target
                        return true
                    end
                    push!(heard, raw[ARP_DEST_SLICE][4])
                end
            end
        end
    end
    @warn "Timed out waiting for ARP beacon" heard_ips="10.20.30." .* string.(Int.(heard))
    return false
end