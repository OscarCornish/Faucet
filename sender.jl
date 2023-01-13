#=

Functions relating to sending packets

    Split into three sections:
        - Generic functions
        - Environment initialisation
        - Sending packets
=#

@debug "sender: Loading..."

using Sockets
using Random: rand
using StaticArrays

#=

    Generic functions

=#

mac(s::AbstractString)::NTuple{6, UInt8} = tuple(map(x->parse(UInt8, x, base=16), split(String(s), ':'))...)
subnet_mask(nbits::Int64)::UInt32 = parse(UInt32, "1" ^ nbits * "0" ^ (32 - nbits), base=2)

is_address_local(ip::UInt32, source::UInt32, subnet_mask::UInt32)::Bool = (ip & subnet_mask) == (source & subnet_mask)
is_address_local(ip::UInt32, ::Nothing, ::Nothing)::Bool = is_address_local(ip, NET_ENV[:src_ip], NET_ENV[:subnet_mask])

to_bytes(x::UInt8)::SVector{1, UInt8} = [x]
to_bytes(x::UInt16)::SVector{2, UInt8} = unsafe_load(Ptr{SVector{2, UInt8}}(Base.unsafe_convert(Ptr{UInt16}, Ref(x))))
to_bytes(x::UInt32)::SVector{4, UInt8} = unsafe_load(Ptr{SVector{4, UInt8}}(Base.unsafe_convert(Ptr{UInt32}, Ref(x))))
to_bytes(x::UInt64)::SVector{8, UInt8} = unsafe_load(Ptr{SVector{8, UInt8}}(Base.unsafe_convert(Ptr{UInt64}, Ref(x))))

#=

    Environment initialisation

=#

NET_ENV = Dict{Symbol, Any}(
    :src_ip => nothing,
    :src_mac => nothing,
    :interface => nothing,
    :subnet_mask => nothing,
    :dest_ip => nothing,
    :dest_first_hop_mac => nothing,
    :target => nothing,
    :queue => nothing,
    :sock => nothing
)

const ip_a_regex = r"^(?<id>\d+): (?<dev_name>[a-zA-Z\d@]+): <[A-Z\-_ ,]+> mtu (?<mtu>\d+) .+\n\s+link\/(?<type>[a-z]+) (?<mac>[a-f\d:]{17}).+\n(?:(?:[\S ]*\n){0,3}    inet (?<addr>(?:\d{1,3}.){3}\d{1,3})\/(?<cidr>\d{1,2}).+\n.+|)"m
const ip_r_regex = r"(?<dest_ip>(?:\d{1,3}\.){3}\d{1,3})(?: via (?<gw>(?:\d{1,3}\.){3}\d{1,3})|) dev (?<if>\w+) src (?<src_ip>(?:\d{1,3}\.){3}\d{1,3})"
const ip_neigh_regex = r"(?<ip>(?:\d{1,3}\.){3}\d{1,3}) dev (?<if>\w+) lladdr (?<mac>[a-f\d:]{17})"

# Do this in a better way, this is clunky
function mac_from_ip(ip::String)::NTuple{6, UInt8}
    for match ∈ eachmatch(ip_a_regex, readchomp(`ip a`))
        if match[:addr] == ip
            return mac(match[:mac])
        end
    end
    return nothing
end
mac_from_ip(ip::IPAddr) = mac_from_ip(string(ip))

# Do this in a better way, this is clunky
function subnet_mask(ip::String)::UInt32
    for match ∈ eachmatch(ip_a_regex, readchomp(`ip a`))
        if match[:addr] == ip
            return subnet_mask(parse(Int64, match[:cidr]))
        end
    end
    return nothing
end
subnet_mask(ip::IPAddr) = subnet_mask(string(ip))

function get_ip_addr(dest_ip::String)::Tuple{String, Union{IPAddr, Nothing}, IPAddr} # Interface, Gateway, Source
    for match ∈ eachmatch(ip_r_regex, readchomp(`ip r get $dest_ip`))
        if match[:dest_ip] == dest_ip
            iface = string(match[:if])
            gw = isnothing(match[:gw]) ? nothing : parse(IPAddr, match[:gw])
            src = parse(IPAddr, match[:src_ip])
            return iface, gw, src
        end
    end
end
get_ip_addr(dest_ip::IPAddr)::Tuple{String, Union{IPAddr, Nothing}, IPAddr} = get_ip_addr(string(dest_ip))

function first_hop_mac(target::String, iface::String)::NTuple{6, UInt8}
    for match ∈ eachmatch(ip_neigh_regex, readchomp(`ip neigh`))
        if match[:ip] == target
            return mac(match[:mac])
        end
    end
    # Force new arp entry
    # TODO: Test if `ip neigh get $addr dev $iface` will perform a new request
    #       in the event the external host is not in the ip neigh table
    #x = readchomp(`ip `)
    return nothing
end
first_hop_mac(target::IPAddr, iface::String)::NTuple{6, UInt8} = first_hop_mac(string(target), iface)

function get_socket()::IOStream
    fd = ccall(:socket, Cint, (Cint, Cint, Cint), AF_PACKET, SOCK_RAW, hton(ETH_P_ALL))
    return fdio(fd)
end

function init_environment(target::Target, q::Channel{Packet})::Dict{Symbol, Any}
    env = Dict{Symbol, Any}()
    # Get dest ip as UInt32
    env[:dest_ip] = target.ip
    # Get src ip from sending interface
    iface, gw, src_ip = get_ip_addr(target.ip)
    # Get sending interface + address
    env[:interface] = iface
    env[:src_ip] = src_ip
    # Get mac address from sending interface
    env[:src_mac] = mac_from_ip(env[:src_ip])
    # Get subnet mask from sending interface
    env[:subnet_mask] = subnet_mask(env[:src_ip])
    # Get first hop mac address
    env[:dest_first_hop_mac] = isnothing(gw) ? first_hop_mac(env[:dest_ip], iface) : first_hop_mac(gw, iface)
    # Target object
    env[:target] = target
    # Queue
    env[:queue] = q
    # Get socket
    env[:sock] = open("dummy-socket", "w") # get_socket()
    @info "Using dummy socket"
    return env
end

@debug "sender: NET_ENV initialisation with empty values" NET_ENV

#=

    Sending packets

=#

@enum Transport_Type begin
    TCP = 0x6
    UDP = 0x11
end

@enum Network_Type begin
    nt_IPv4 = 0x0800
end

to_net(in::Unsigned)::Vector{UInt8} = to_bytes(hton(in))
to_net(in::IPAddr)::Vector{UInt8} = to_bytes(hton(in.host))
to_net(in::Vector{UInt8})::Vector{UInt8} = reverse(in)

function craft_ethernet_header(t::Network_Type; source_mac::Union{NTuple{6, UInt8}, Nothing} = nothing, dest_mac::Union{NTuple{6, UInt8}, Nothing} = nothing)::Vector{UInt8}
    header = Vector{UInt8}()
    source_mac = isnothing(source_mac) ? NET_ENV[:src_mac] : source_mac
    append!(header, source_mac)
    dest_mac = isnothing(dest_mac) ? NET_ENV[:dest_first_hop_mac] : dest_mac
    append!(header, dest_mac)
    append!(header, to_net(UInt16(t)))
    return header
end

function craft_network_header(t::Network_Type, transport::Transport_Type, kwargs::Dict{Symbol, Any})::Vector{UInt8}
    if t == nt_IPv4::Network_Type
        return craft_ip_header(transport; kwargs...)
    else
        error("Unsupported network type: $t")
    end
end

function ip_checksum(header::Vector{UInt8})::UInt16
    checksum = sum([UInt32(header[i]) << 8 + UInt32(header[i+1]) for i in 1:2:lastindex(header)])
    return ~UInt16((checksum >> 16) + (checksum & 0xFFFF))
end

function craft_ip_header(
            protocol::Transport_Type;
            version::Union{Nothing, UInt8} = nothing,
            ihl::Union{Nothing, UInt8} = nothing,
            dscp::Union{Nothing, UInt8} = nothing,
            ecn::Union{Nothing, UInt8} = nothing,
            total_length::Union{Nothing, UInt16} = nothing,
            identification::Union{Nothing, UInt16} = nothing,
            flags::Union{Nothing, UInt8} = nothing,
            fragment_offset::Union{Nothing, UInt16} = nothing,
            ttl::Union{Nothing, UInt8} = nothing,
            header_checksum::Union{Nothing, UInt16} = nothing,
            source_ip::Union{Nothing, UInt32} = nothing,
            dest_ip::Union{Nothing, UInt32} = nothing
        )::Vector{UInt8}
    ip_header = Vector{UInt8}()
    version = isnothing(version) ? 0x4 : version
    ihl = isnothing(ihl) ? 0x5 : ihl
    append!(ip_header, to_net(version << 4 | ihl & 0xf))
    dscp = isnothing(dscp) ? 0x0 : dscp
    ecn = isnothing(ecn) ? 0x0 : ecn
    append!(ip_header, to_net(dscp << 2 | ecn & 0x3))
    total_length = isnothing(total_length) ? 0x0000 : total_length
    append!(ip_header, to_net(total_length))
    identification = isnothing(identification) ? rand(UInt16) : identification
    append!(ip_header, to_net(identification))
    flags = isnothing(flags) ? 0b000 : flags & 0b111
    fragment_offset = isnothing(fragment_offset) ? 0x0000 : fragment_offset & 0x1fff
    append!(ip_header, to_net(flags << 13 | fragment_offset))
    ttl = isnothing(ttl) ? 0xff : ttl
    append!(ip_header, to_net(ttl))
    append!(ip_header, to_net(UInt8(protocol)))
    checksum = isnothing(header_checksum) ? 0x0000 : header_checksum
    append!(ip_header, to_net(checksum))
    source_ip = isnothing(source_ip) ? NET_ENV[:src_ip] : source_ip
    append!(ip_header, to_net(source_ip))
    dest_ip = isnothing(dest_ip) ? NET_ENV[:dest_ip] : dest_ip
    append!(ip_header, to_net(dest_ip))
    # Calculate checksum with zeros, then replace after calculation
    if isnothing(header_checksum)
        ip_header[11:12] = to_net(ip_checksum(ip_header))
    end
    return ip_header
end

function craft_transport_header(t::Transport_Type, packet::Vector{UInt8}, payload::Vector{UInt8}, kwargs::Dict{Symbol, Any})::Vector{UInt8}
    if t == TCP::Transport_Type
        return craft_tcp_header(packet, payload; kwargs...)
    elseif t == UDP::Transport_Type
        return craft_udp_header(payload; kwargs...)
    else
        error("Unknown transport type: $t")
    end
end

function tcp_checksum(packet::Vector{UInt8}, tcp_header::Vector{UInt8}, payload::Vector{UInt8})::UInt16
    pseudo_header = Vector{UInt8}()
    append!(pseudo_header, to_net(packet[13:16]))
    append!(pseudo_header, to_net(packet[17:20]))
    append!(pseudo_header, to_net(UInt8(0x0)))
    append!(pseudo_header, to_net(UInt8(0x6)))
    append!(pseudo_header, to_net(UInt16(length(tcp_header) + length(payload))))
    checksum = sum([UInt32(pseudo_header[i]) << 8 + UInt32(pseudo_header[i+1]) for i in 1:2:lastindex(pseudo_header)])
    checksum += sum([UInt32(tcp_header[i]) << 8 + UInt32(tcp_header[i+1]) for i in 1:2:lastindex(tcp_header)])
    checksum += sum([UInt32(payload[i]) << 8 + UInt32(payload[i+1]) for i in 1:2:lastindex(payload)])
    return ~UInt16((checksum >> 16) + (checksum & 0xFFFF))
end

function craft_tcp_header(
            packet::Vector{UInt8},
            payload::Vector{UInt8};
            sport::Union{Nothing, UInt16} = nothing,
            dport::Union{Nothing, UInt16} = nothing,
            seq::Union{Nothing, UInt32} = nothing,
            ack::Union{Nothing, UInt32} = nothing,
            data_offset::Union{Nothing, UInt8} = nothing,
            reserved::Union{Nothing, UInt8} = nothing,
            flags::Union{Nothing, UInt8} = nothing,
            window::Union{Nothing, UInt16} = nothing,
            checksum::Union{Nothing, UInt16} = nothing,
            urgent_pointer::Union{Nothing, UInt16} = nothing,
            options::Union{Nothing, Vector{UInt8}} = nothing
        )::Vector{UInt8}
    tcp_header = Vector{UInt8}()
    sport = isnothing(sport) ? rand(UInt16) : sport
    append!(tcp_header, to_net(sport))
    dport = isnothing(dport) ? rand(UInt16) : dport
    append!(tcp_header, to_net(dport))
    seq = isnothing(seq) ? rand(UInt32) : seq
    append!(tcp_header, to_net(seq))
    # Observe flags and alter other fields accordingly (ack, urgent_pointer, etc.)
    if isnothing(flags)
        flags = 0x000
    else
        if flags & 0x10 != 0x0
            ack = isnothing(ack) ? rand(UInt32) : ack
        end
        if flags & 0x20 != 0x0
            urgent_pointer = isnothing(urgent_pointer) ? rand(UInt16) : urgent_pointer
        end
    end
    ack = isnothing(ack) ? 0x00000000 : ack
    append!(tcp_header, to_net(ack))
    data_offset = isnothing(data_offset) ? 0x05 : data_offset
    reserved = isnothing(reserved) ? 0x000 : reserved
    do_flags = UInt16(data_offset) << 12 | UInt16(reserved) << 9 | UInt16(flags) & 0x01ff
    append!(tcp_header, to_net(do_flags))
    window = isnothing(window) ? 0xffff : window
    append!(tcp_header, to_net(window))
    check = isnothing(checksum) ? 0x0000 : checksum
    append!(tcp_header, to_net(check))
    urgent_pointer = isnothing(urgent_pointer) ? 0x0000 : urgent_pointer
    append!(tcp_header, to_net(urgent_pointer))
    if !isnothing(options)
        error("No options handling implemented")
    end
    if isnothing(checksum)
        check = tcp_checksum(packet, tcp_header, payload)
        @debug "Calculated TCP checksum: " checksum=check
        tcp_header[17:18] = to_net(check)
    end
    return tcp_header
end

function craft_packet(;
            payload::Vector{UInt8},
            network_type::Network_Type = nt_IPv4::Network_Type,
            transport_type::Transport_Type = TCP::Transport_Type,
            EtherKWargs::Dict{Symbol, Any} = Dict{Symbol, Any}(),
            NetworkKwargs::Dict{Symbol, Any} = Dict{Symbol, Any}(),
            TransportKwargs::Dict{Symbol, Any} = Dict{Symbol, Any}()
        )::Vector{UInt8}

    packet = Vector{UInt8}()

    # Craft Ethernet header
    ether_header = craft_ethernet_header(network_type; EtherKWargs...)
    append!(packet, ether_header)
    ether_length = length(packet)
    @debug "Ethernet header: " len=ether_length packet

    # Get IP header
    network_header = craft_network_header(network_type, transport_type, NetworkKwargs)
    append!(packet, network_header)
    @debug "↓ Network header: " len=length(packet) packet 


    transport_header = craft_transport_header(transport_type, packet, payload, TransportKwargs)
    if packet[17:18] == [0x00, 0x00]
        len = to_net(UInt16(length(network_header) + length(transport_header) + length(payload)))
        @debug "IPv4 total length: " len
        packet[ether_length+3:ether_length+4] = len
    end

    # Craft Transport header
    append!(packet, transport_header)
    @debug "↓ Transport header: " len=length(packet) packet
    
    # Append payload
    append!(packet, payload)

    return packet
end

function send(packet::Vector{UInt8})
    return write(NET_ENV[:sock], packet)
end

@debug "sender: Packet crafting + sending functions defined"

# Covert packet sending

function send_covert_payload(raw_payload::Vector{UInt8}, methods::Tuple{covert_method, covert_method}=covert_channels, net_env::Dict{Symbol, Any}=NET_ENV)
    payload = enc(raw_payload)
    bits = *(bitstring.(payload)...)
    pointer = 1
    current_method_index = 1
    time_interval = 60 # Don't want packets to send until we have determined which type is best
    # Send meta sentinel to target using methods[1]
    method = methods[current_method_index]
    method_kwargs = method.encode_functions[1](net_env, net_env[:queue])::Dict{Symbol, Any} # Init method kwargs
    sentinel_pkt = method.encode_functions[2](craft_meta_payload(SENTINEL, method.payload_size); method_kwargs...)
    send(sentinel_pkt)
    @info "Sent meta sentinel" via=method.name
    sleep(time_interval)
    while pointer <= lastindex(bits)
        method_index, time_interval = determine_method(methods)::Tuple{Int64, Int64}
        if method_index != current_method_index
            # Send meta packet to tell target to switch methods
            method.encode_functions[2](craft_meta_payload(method_index, method.payload_size); method_kwargs...)
            # Switch methods
            method = methods[method_index]
            method_kwargs = method.encode_functions[1](net_env, net_env[:queue])
            current_method_index = method_index
            @info "Switched method" method=method.name interval=time_interval
        end
        # Send payload packet
        if pointer+method.payload_size-1 > lastindex(bits)
            payload = "0" * bits[pointer:lastindex(bits)] * "0" * (method.payload_size - (lastindex(bits) - pointer + 1))
        else
            payload = "0" * bits[pointer:pointer+method.payload_size-1]
        end
        pointer += method.payload_size-1
        send(method.encode_functions[2](payload, method_kwargs...))
        @debug "Sent payload packet" method=method.name payload=payload
        sleep(time_interval)
    end
end