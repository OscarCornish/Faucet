using ..CovertChannels: determine_method, covert_method, init, encode

# IP checksum
function checksum(message::Vector{UInt8})::UInt16
    checksum = sum([UInt32(message[i]) << 8 + UInt32(message[i+1]) for i in 1:2:length(message)])
   checksum = ~((checksum & 0xffff) + (checksum >> 16)) & 0xffff
end

# TCP and UDP checksum
function checksum(packet::Vector{UInt8}, tcp_header::Vector{UInt8}, payload::Vector{UInt8})::UInt16
    header_length = length(tcp_header)
    segment_length = header_length + length(payload)
    buffer = zeros(UInt8, 12+segment_length)

    buffer[1:4] = packet[27:30] # Source IP
    buffer[5:8] = packet[31:34] # Destination IP
    buffer[9] = UInt8(0) # Reserved 
    buffer[10] = packet[24] # Protocol
    
    buffer[11:12] = to_bytes(UInt16(segment_length)) # TCP segment length

    for i ∈ 1:length(tcp_header)
        buffer[12+i] = tcp_header[i]
    end

    for i ∈ 1:length(payload)
        buffer[12+header_length+i] = payload[i]
    end     
    return checksum(buffer)
end

#=

    Layer 2: Data link

=#

function craft_datalink_header(t::Link_Type, nt::Network_Type, env::Dict{Symbol, Any}, kwargs::Dict{Symbol, Any})::Vector{UInt8}
    if t == Ethernet::Link_Type
        return craft_ethernet_header(nt, env; kwargs...)
    else
        error("Unsupported link type: $t")
    end
end

function craft_ethernet_header(t::Network_Type, env::Dict{Symbol, Any}; source_mac::Union{NTuple{6, UInt8}, Nothing} = nothing, dest_mac::Union{NTuple{6, UInt8}, Nothing} = nothing)::Vector{UInt8}
    header = Vector{UInt8}()
    dest_mac = isnothing(dest_mac) ? env[:dest_first_hop_mac] : dest_mac
    append!(header, dest_mac)
    source_mac = isnothing(source_mac) ? env[:src_mac] : source_mac
    append!(header, source_mac)
    append!(header, to_net(UInt16(t)))
    return header
end

#=

    Layer 3: Network

=#

function craft_network_header(t::Network_Type, transport::Transport_Type, env::Dict{Symbol, Any}, kwargs::Dict{Symbol, Any})::Vector{UInt8}
    if t == IPv4::Network_Type
        return craft_ip_header(transport, env; kwargs...)
    elseif t == ARP::Network_Type
        return craft_arp_header(env; kwargs...)
    else
        error("Unsupported network type: $t")
    end
end

function craft_arp_header(
    env::Dict{Symbol, Any};
    hardware_type::Union{Nothing, UInt16} = 0x0001,
    protocol_type::Union{Nothing, UInt16} = 0x0800,
    hardware_size::Union{Nothing, UInt8} = 0x06,
    protocol_size::Union{Nothing, UInt8} = 0x04,
    operation::Union{Nothing, UInt16} = 0x0001,
    SHA::Union{Nothing, NTuple{6, UInt8}} = nothing,
    SPS::Union{Nothing, NTuple{4, UInt8}} = nothing,
    THA::Union{Nothing, NTuple{6, UInt8}} = (0, 0, 0, 0, 0, 0),
    TPS::Union{Nothing, NTuple{4, UInt8}} = nothing
    )::Vector{UInt8}
    header = Vector{UInt8}()
    append!(header, to_net(hardware_type))
    append!(header, to_net(protocol_type))
    append!(header, to_net(hardware_size))
    append!(header, to_net(protocol_size))
    append!(header, to_net(operation))
    SHA = isnothing(SHA) ? env[:src_mac] : SHA
    append!(header, SHA)
    SPS = isnothing(SPS) ? env[:src_ip] : SPS
    append!(header, to_net(SPS))
    append!(header, THA)
    TPS = isnothing(TPS) ? env[:dest_ip] : TPS
    append!(header, to_net(TPS))
    return header
end

function ip_checksum(header::Vector{UInt8})::UInt16
    checksum = sum([UInt32(header[i]) << 8 + UInt32(header[i+1]) for i in 1:2:lastindex(header)])
    return ~UInt16((checksum >> 16) + (checksum & 0xFFFF))
end

function craft_ip_header(
            protocol::Transport_Type,
            env::Dict{Symbol, Any};
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
    ttl = isnothing(ttl) ? 0xf3 : ttl
    append!(ip_header, to_net(ttl))
    append!(ip_header, to_net(UInt8(protocol)))
    _checksum = isnothing(header_checksum) ? 0x0000 : header_checksum
    append!(ip_header, to_net(_checksum))
    source_ip = isnothing(source_ip) ? env[:src_ip].host : source_ip
    append!(ip_header, to_net(to_bytes(source_ip)))
    dest_ip = isnothing(dest_ip) ? env[:dest_ip].host : dest_ip
    append!(ip_header, to_net(to_bytes(dest_ip)))
    return ip_header
end

#=

    Layer 4: Transport

=#

function craft_transport_header(t::Transport_Type, env::Dict{Symbol, Any}, packet::Vector{UInt8}, payload::Vector{UInt8}, kwargs::Dict{Symbol, Any})::Vector{UInt8}
    if t == UDP::Transport_Type
        return craft_udp_header(payload, env; kwargs...)
    elseif t == TCP::Transport_Type
        return craft_tcp_header(packet, payload, env; kwargs...)
    else
        error("Unsupported transport type: $t")
    end
end

function craft_tcp_header(
            packet::Vector{UInt8},
            payload::Vector{UInt8},
            ::Dict{Symbol, Any};
            sport::Union{Nothing, UInt16} = nothing,
            dport::Union{Nothing, UInt16} = nothing,
            seq::Union{Nothing, UInt32} = nothing,
            ack::Union{Nothing, UInt32} = nothing,
            data_offset::Union{Nothing, UInt8} = nothing,
            reserved::Union{Nothing, UInt8} = nothing,
            flags::Union{Nothing, UInt16} = nothing,
            window::Union{Nothing, UInt16} = nothing,
            _checksum::Union{Nothing, UInt16} = nothing,
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
    check = isnothing(_checksum) ? 0x0000 : checksum
    append!(tcp_header, to_net(check))
    urgent_pointer = isnothing(urgent_pointer) ? 0x0000 : urgent_pointer
    append!(tcp_header, to_net(urgent_pointer))
    if !isnothing(options)
        error("No options handling implemented")
    end
    if isnothing(_checksum)
        tcp_header[17:18] = to_net(checksum(packet, tcp_header, payload))
    end
    return tcp_header
end

#=

    Crafting the packets

=#

function craft_packet(;
            payload::Vector{UInt8}, env::Dict{Symbol, Any},
            network_type::Network_Type = IPv4::Network_Type,
            transport_type::Transport_Type = TCP::Transport_Type,
            EtherKWargs::Dict{Symbol, Any} = Dict{Symbol, Any}(),
            NetworkKwargs::Dict{Symbol, Any} = Dict{Symbol, Any}(),
            TransportKwargs::Dict{Symbol, Any} = Dict{Symbol, Any}()
        )::Vector{UInt8}

    packet = Vector{UInt8}()
    #@debug "Crafting packet" p=payload ek=EtherKWargs nk=NetworkKwargs tk=TransportKwargs

    # Craft Datalink header
    dl_header = craft_datalink_header(Ethernet::Link_Type, network_type, env, EtherKWargs)
    append!(packet, dl_header)
    dl_length = length(packet)

    # Get network header
    network_header = craft_network_header(network_type, transport_type, env, NetworkKwargs)
    append!(packet, network_header)


    transport_header = craft_transport_header(transport_type, env, packet, payload, TransportKwargs)
    if network_type == IPv4::Network_Type && packet[17:18] == [0x00, 0x00]
        len = to_net(UInt16(length(network_header) + length(transport_header) + length(payload)))
        packet[dl_length+3:dl_length+4] = len
        # Perform checksum after setting length
    end
    if network_type == IPv4::Network_Type && packet[dl_length+11:dl_length+12] == [0x00, 0x00]
        packet[dl_length+11:dl_length+12] = to_net(checksum(packet[dl_length+1:dl_length+length(network_header)]))
    end
    # Craft Transport header
    append!(packet, transport_header)
    
    # Append payload
    append!(packet, payload)

    return packet
end

"""
    ARP_Beacon(payload::NTuple{6, UInt8})

Send out a beacon with the given payload. The payload is a tuple of 6 bytes.
"""
function ARP_Beacon(payload::UInt8, source_ip::IPAddr, send_socket::IOStream=get_socket(Int32(17), Int32(3), Int32(0xff00)))::Nothing
    src_mac = mac_from_ip(source_ip, :local) # This function is used by the receiver, so the src addr is the target addr
    src_ip = to_net(source_ip)
    dst_ip = [src_ip...; payload]
    iface = get_dev_from_ip(source_ip)
    @info "Sending ARP beacon" src_mac=src_mac src_ip=src_ip dst_ip=dst_ip payload

    packet = craft_packet(
        payload = Vector{UInt8}(),
        network_type = ARP::Network_Type,
        EtherKWargs = Dict{Symbol, Any}(
            :src_mac => src_mac, # Get from regex...
            :dst_mac => (0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        ),
        NetworkKwargs = Dict{Symbol, Any}(
            :SHA => src_mac,
            :THA => (0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
            :SPS => src_ip, # Target <- Have from target...
            :TPS => dst_ip # first 3 bytes of src_ip, + payload
        )
    )
    # Send packet
    sendto(send_socket, packet, iface)
    return nothing
end
ARP_Beacon(payload::NTuple{6, UInt8}, source_ip::String) = ARP_Beacon(payload, IPv4Addr(source_ip))


function send_packet(packet::Vector{UInt8}, net_env::Dict{Symbol, Any})::Nothing
    bytes = sendto(net_env[:sock]::IOStream, packet, net_env[:interface]::String)
    @assert (bytes == length(packet)) "Sent $bytes bytes, expected $(length(packet))"
    return nothing
end

function send_sentinel_packet(m::covert_method, net_env::Dict{Symbol, Any}, template::Dict{Symbol, Any})::Nothing
    send_packet(craft_packet(;encode(m, craft_sentinel_payload(m.payload_size); template)...), net_env)
end

function send_method_change_packet(m::covert_method, method_index::Int, net_env::Dict{Symbol, Any}, template::Dict{Symbol, Any})::UInt8
    (payload, integrity_key) = craft_change_method_payload(m, method_index)
    send_packet(craft_packet(;encode(m, payload; template)...), net_env)
    return integrity_key
end

function send_discard_chunk_packet(m::covert_method, net_env::Dict{Symbol, Any}, template::Dict{Symbol, Any})::Nothing
    send_packet(craft_packet(;encode(m, craft_discard_chunk_payload(m.payload_size); template)...), net_env)
end

# function send_meta_packet(m::covert_method, net_env::Dict{Symbol, Any}, payload::Union{String, Unsigned, Int64}, template::Dict{Symbol, Any})::Nothing
#     return send_packet(craft_packet(;encode(m, craft_meta_payload(payload, m.payload_size); template)...), net_env)
# end

function send_packet(m::covert_method, net_env::Dict{Symbol, Any}, payload::String, template::Dict{Symbol, Any})::Nothing
    return send_packet(craft_packet(;encode(m, payload; template)...), net_env)
end

function send_covert_payload(raw_payload::Vector{UInt8}, methods::Vector{covert_method}, net_env::Dict{Symbol, Any})
    current_method_index = 1
    pointer = 1
    chunk_pointer = pointer
    time_interval = 5 # Don't want packets to send until we have determined which type is best
    @warn "Inital time interval " time_interval
    
    # Encrypt payload and append length, store it as a bitstring
    payload = enc(raw_payload)
    bits = *(bitstring.(payload)...)
    bits *= lstrip(bitstring(Int64(length(bits) / 8)), '0') # Append length of payload, we will use this to determine where the payload ends later
    
    # Send meta sentinel to target using methods[1]
    method = methods[current_method_index]
    method_kwargs = init(method, net_env)
    @info "Sending sentinel packet" method=method.name
    send_sentinel_packet(method, net_env, method_kwargs)

    # Sleep so that when we determine_method we actually have a good understanding of the environment
    sleep(time_interval)
    while pointer <= lastindex(bits)
        method_index, time_interval = determine_method(methods, net_env)
        if method_index != current_method_index
            # Send meta packet to tell target to switch methods
            # Make custom method for changing methods, returning the key for integrity check
            key = send_method_change_packet(method, method_index, net_env, method_kwargs)
            # It is likely I've messed up the pointer here...
            integrity = integrity_check(bits[chunk_pointer:pointer-1], key)
            
            # Switch methods
            method = methods[method_index]
            method_kwargs = init(method, net_env)
            current_method_index = method_index
            @info "Switched method" method=method.name interval=time_interval
            
            data = await_arp_beacon(net_env[:target_ip], 5)
            if !isnothing(data) && integrity == data # Success!
                chunk_pointer = pointer
            else # Failure, resend chunk
                pointer = chunk_pointer
                @warn "Failed integrity check" method=method.name data
                send_discard_chunk_packet(method, net_env, method_kwargs)
            end
        end
        # Send payload packet
        if pointer+method.payload_size-1 > lastindex(bits)
            payload = rpad("0" * bits[pointer:lastindex(bits)], method.payload_size, '0')
            @debug "Packet covert payload (Without MP)(FINAL)" payload=bits[pointer:lastindex(bits)] chunk_length=pointer-chunk_pointer
        else
            payload = "0" * bits[pointer:pointer+method.payload_size-2]
            @debug "Packet covert payload (Without MP)" payload=bits[pointer:pointer+method.payload_size-2] chunk_length=pointer-chunk_pointer
        end
        pointer += method.payload_size-1
        send_packet(method, net_env, payload, method_kwargs)
        sleep(time_interval)
    end
    send_sentinel_packet(method, net_env, method_kwargs)
    send_sentinel_packet(method, net_env, method_kwargs)
    @info "Endded communication via SENTINEL" via=method.name
end