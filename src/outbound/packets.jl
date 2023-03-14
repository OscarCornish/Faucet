using ..CovertChannels: determine_method, covert_method, init, encode

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
    source_mac = isnothing(source_mac) ? env[:src_mac] : source_mac
    append!(header, source_mac)
    dest_mac = isnothing(dest_mac) ? env[:dest_first_hop_mac] : dest_mac
    append!(header, dest_mac)
    append!(header, to_net(UInt16(t)))
    return header
end

#=

    Layer 3: Network

=#

function craft_network_header(t::Network_Type, transport::Transport_Type, env::Dict{Symbol, Any}, kwargs::Dict{Symbol, Any})::Vector{UInt8}
    if t == IPv4::Network_Type
        return craft_ip_header(transport, env; kwargs...)
    else
        error("Unsupported network type: $t")
    end
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
    checksum = isnothing(header_checksum) ? 0x0000 : header_checksum
    append!(ip_header, to_net(checksum))
    source_ip = isnothing(source_ip) ? env[:src_ip] : source_ip
    append!(ip_header, to_net(source_ip))
    dest_ip = isnothing(dest_ip) ? env[:dest_ip] : dest_ip
    append!(ip_header, to_net(dest_ip))
    # Calculate checksum with zeros, then replace after calculation
    if isnothing(header_checksum)
        ip_header[11:12] = to_net(ip_checksum(ip_header))
    end
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
        #@debug "Calculated TCP checksum: " checksum=check
        tcp_header[17:18] = to_net(check)
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
    #@info "Crafting packet" p=payload ek=EtherKWargs nk=NetworkKwargs tk=TransportKwargs

    # Craft Ethernet header
    ether_header = craft_datalink_header(Ethernet::Link_Type, network_type, env, EtherKWargs)
    append!(packet, ether_header)
    ether_length = length(packet)
    #@debug "Ethernet header: " len=ether_length packet

    # Get IP header
    network_header = craft_network_header(network_type, transport_type, env, NetworkKwargs)
    append!(packet, network_header)
    #@debug "↓ Network header: " len=length(packet) packet 


    transport_header = craft_transport_header(transport_type, env, packet, payload, TransportKwargs)
    if network_type == IPv4::Network_Type && packet[17:18] == [0x00, 0x00]
        len = to_net(UInt16(length(network_header) + length(transport_header) + length(payload)))
        #@debug "IPv4 total length: " len
        packet[ether_length+3:ether_length+4] = len
    end

    # Craft Transport header
    append!(packet, transport_header)
    #@debug "↓ Transport header: " len=length(packet) packet
    
    # Append payload
    append!(packet, payload)

    return packet
end

function send_packet(packet::Vector{UInt8}, net_env::Dict{Symbol, Any})::Nothing
    #@debug "Sending packet" sock=net_env[:sock] interface=net_env[:interface]
    bytes = sendto(net_env[:sock]::IOStream, packet, net_env[:interface]::String)
    #@debug "Sent packet" bytes=bytes
    @assert (bytes == length(packet)) "Sent $bytes bytes, expected $(length(packet))"
    return nothing
end
function send_meta_packet(m::covert_method, net_env::Dict{Symbol, Any}, payload::Union{String, Unsigned, Int64}, template::Dict{Symbol, Any})::Nothing
    return send_packet(craft_packet(;encode(m, craft_meta_payload(payload, m.payload_size); template)...), net_env)
end
function send_packet(m::covert_method, net_env::Dict{Symbol, Any}, payload::String, template::Dict{Symbol, Any})::Nothing
    return send_packet(craft_packet(;encode(m, payload; template)...), net_env)
end

function send_covert_payload(raw_payload::Vector{UInt8}, methods::Vector{covert_method}, net_env::Dict{Symbol, Any})
    #@warn "NOT ENCRYPTING PAYLOAD FOR TESTING PURPOSES"
    #payload = enc(raw_payload)
    payload = raw_payload
    bits = *(bitstring.(payload)...)
    pointer = 1
    current_method_index = 1
    time_interval = 5 # Don't want packets to send until we have determined which type is best
    #@warn "Inital time interval " time_interval
    # Send meta sentinel to target using methods[1]
    method = methods[current_method_index]
    method_kwargs = init(method, net_env)
    send_meta_packet(method, net_env, SENTINEL, method_kwargs)
    #@info "Sent meta sentinel" via=method.name
    sleep(time_interval)
    while pointer <= lastindex(bits)
        method_index, time_interval = determine_method(methods, net_env)
        if method_index != current_method_index
            # Send meta packet to tell target to switch methods
            send_meta_packet(method, net_env, method_index, method_kwargs)
            # Switch methods
            method = methods[method_index]
            method_kwargs = init(method, net_env)
            current_method_index = method_index
            #@info "Switched method" method=method.name interval=time_interval
        end
        # Send payload packet
        if pointer+method.payload_size-1 > lastindex(bits)
            payload = "0" * bits[pointer:lastindex(bits)] * "0" ^ (method.payload_size - (lastindex(bits) - pointer + 1))
        else
            payload = "0" * bits[pointer:pointer+method.payload_size-1]
        end
        pointer += method.payload_size-1
        send_packet(method, net_env, payload, method_kwargs)
        #@debug "Sent payload packet" method=method.name payload=payload
        sleep(time_interval)
    end
end    