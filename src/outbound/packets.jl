using AES

# Encrypt a payload, using our PSK and IV
enc(plaintext::Vector{UInt8})::Vector{UInt8} = encrypt(plaintext, AESCipher(;key_length=128, mode=AES.CBC, key=target.AES_PSK); iv=target.AES_IV).data

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
    append!(header, SPS)
    append!(header, THA)
    TPS = isnothing(TPS) ? env[:dest_ip] : TPS
    append!(header, TPS)
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
function ARP_Beacon(payload::UInt8, source_ip::IPv4Addr, send_socket::IOStream=get_socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW))::Nothing
    src_mac = mac_from_ip(source_ip, :local) # This function is used by the receiver, so the src addr is the target addr
    src_ip = _to_bytes(source_ip.host)
    dst_ip = [src_ip[1:3]...; payload]
    iface = get_dev_from_ip(source_ip)
    @debug "Sending ARP beacon" encoded_byte=payload

    packet = craft_packet(
        payload = Vector{UInt8}(),
        env = Dict{Symbol, Any}(),
        network_type = ARP::Network_Type,
        EtherKWargs = Dict{Symbol, Any}(
            :source_mac => src_mac, # Get from regex...
            :dest_mac => (0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        ),
        NetworkKwargs = Dict{Symbol, Any}(
            :SHA => src_mac,
            :THA => (0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
            :SPS => NTuple{4, UInt8}(src_ip), # Target <- Have from target...
            :TPS => NTuple{4, UInt8}(dst_ip) # first 3 bytes of src_ip, + payload
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

# The below functions are just wrappers of send_packet (sendto) and their respective functions in covert_channels

function send_packet(m::covert_method, net_env::Dict{Symbol, Any}, payload::String, template::Dict{Symbol, Any})::Nothing
    return send_packet(craft_packet(;encode(m, payload; template)...), net_env)
end

function send_sentinel_packet(m::covert_method, net_env::Dict{Symbol, Any}, template::Dict{Symbol, Any})::Nothing
    open("../Testing-Data/timings/$(ARGS[3]).timings", "a") do io
        write(io, "SENTINEL:$(m.name):$(time_ns())\n")
    end
    send_packet(craft_packet(;encode(m, craft_sentinel_payload(m.payload_size); template)...), net_env)
end

function send_recovery_packet(m::covert_method, last_verification::Tuple{Int64, UInt8}, known_host::UInt8, net_env::Dict{Symbol, Any}, template::Dict{Symbol, Any})::Nothing
    send_packet(craft_packet(;encode(m, craft_recovery_payload(m.payload_size, last_verification, known_host); template)...), net_env)
end

function send_method_change_packet(m::covert_method, method_index::Int, offset::UInt8, net_env::Dict{Symbol, Any}, template::Dict{Symbol, Any})::Nothing
    payload = craft_change_method_payload(method_index, offset, m.payload_size)
    send_packet(craft_packet(;encode(m, payload; template)...), net_env)
end

function send_discard_chunk_packet(m::covert_method, bits::String, pointer::Int64, net_env::Dict{Symbol, Any}, template::Dict{Symbol, Any})::Int64
    pointer_offset, payload = craft_discard_chunk_payload(m.payload_size, bits, pointer)
    send_packet(craft_packet(;encode(m, payload; template)...), net_env)
    return pointer_offset
end

"""
    pad_transmission(payload::bitstring, method::Symbol=:short)::bitstring

    Take the payload and pad it to the nearest byte boundary.

    Methods are:
        :short => Uses minimal padding, but is less covert
        :covert => Uses more padding, but is more covert
"""
function pad_transmission(raw::String, method::Symbol=PADDING_METHOD)::String
    if method == :short
        return raw * "1"
    elseif method == :covert
        # We know our encrypted payload is a multiple of 128 bits, so divide by 128 to get the number of "segments"
        return raw * lstrip(bitstring(Int64(length(raw) / 128)), '0')
    else
        error("Unknown padding method $method")
    end
end

"""
    pad_packet_payload(packet_payload::bitstring, capacity::Int, transmission::bitstring, method::Symbol=:short)::bitstring

    Pad the packet payload to the size of the capacity, depending on the method.

    Transmission is the orginal, unpadded, bits for transmission (post-encryption), used for verification.

    Handles same methods as ['pad_transmission'](@ref)
"""
function pad_packet_payload(packet_payload::String, capacity::Int, transmission::String, method::Symbol=PADDING_METHOD)::String
    if method == :short
        padding = "0" ^ (capacity - length(packet_payload))
        @assert remove_padding(pad_transmission(transmission) * padding, method) == transmission "Padding is not valid (:short)"
        return packet_payload * padding
    elseif method == :covert
        padding = join([rand(['0', '1']) for _ in 1:capacity - length(packet_payload)])
        # Random padding CANNOT be a valid length of the payload
        #  it's very likely this will happen, but just in case...
        while remove_padding(pad_transmission(transmission, method) * padding, method) != transmission
            padding = join([rand(['0', '1']) for _ in 1:capacity - length(packet_payload)])
        end
        return packet_payload * padding
    else
        error("Unknown padding method $method")
    end
end

"""
Send a packet using an adaptive covert communication channel
"""
function send_covert_payload(raw_payload::Vector{UInt8}, methods::Vector{covert_method}, net_env::Dict{Symbol, Any})
    # Blacklist our current host, as the target may arp us unrelated to the covert channel
    host_blacklist = [UInt8(hton(net_env[:dest_ip].host) & 0x000000ff)]
    
    # Protocol blacklisting variables:
    # Current packet + `penalty_size` : When it is no longer "blacklisted" (-1 for permenant blacklist)
    penalty_size = 30
    # Initialise protocol failure counter
    protocol_failures = 0
    # Number of failures until we switch to next method
    max_failures = 2
    # (Protocol, Release_packet)
    protocol_blacklist = Vector{Tuple{Int64, Int64}}()

    # Initialise sender variables:
    # By default, we start with the first method
    current_method_index = 1
    # Get the method from the vector
    method = methods[current_method_index]
    # And initialise it
    method_kwargs = init(method, net_env)
    # Pointer to the current bit we are sending (start with the first)
    pointer = 1
    # Pointer to the start of the current chunk
    chunk_pointer = pointer
    # Max data packets between integrity checks
    integrity_interval = 6
    # Number of packets sent
    packet_count = 0
    # Time to wait for a (challenge) response from the target
    check_timeout = 5
    # The padding we send to the target with our final payload will be part of the integrity check, so store it
    final_padding = ""
    # When we have sent the final payload we go back to perform an integrity check, but we don't want to send packets after so we set this flag
    finished = false

    # Initialise the payload:
    payload = enc(raw_payload)
    # Convert the payload to a bitstring
    _bits = *(bitstring.(payload)...)
    # Pad the transmission, because we may have to append noise to it later (to fit a methods capacity)
    bits = pad_transmission(_bits)
    
    # Give the environment queue some time to populate, so sleep a bit
    #  If we don't do this then our chosen method will be volatile...  
    time_interval = 5
    @warn "Inital time interval " time_interval
    sleep(time_interval)
    
    # Recovery mode variables:
    # Whether we are in recovery mode
    recovery_mode = false
    # At 0 packets we know what the payload is (0x00)
    last_verification_packet_count = packet_count
    last_verification_time = time()
    last_integrity = (0, 0x00) # (length (in s), integrity value)
    # Time interval, packet interval
    #  to start, we don't want to go straight into recovery mode, but we do want the possibility - so just add a delay
    #  50 seconds, 6 packets
    recovery_timeouts = (50, integrity_interval)

    @info "Sending sentinel packet" method=method.name
    # Start communication with a sentinel packet
    send_sentinel_packet(method, net_env, method_kwargs)
    while pointer <= lastindex(bits)
        # Remove blacklisted protocols that have served their penalty
        for (idx, (proto, penal)) ∈ enumerate(protocol_blacklist)
            # If the penalty has expired, remove it
            if penal <= packet_count
                @debug "Removing protocol from blacklist" protocol=methods[proto].name
                deleteat!(protocol_blacklist, idx)
            end
        end

        if recovery_mode
            @info "Entering recovery mode" timeouts=recovery_timeouts
            # Wait until the target is in recovery mode 1.5x what we think it should wait, to be sure
            while !(time() - last_verification_time > recovery_timeouts[1] * 1.5 || packet_count - last_verification_packet_count > recovery_timeouts[2] * 1.5)
                sleep(1)
            end
            # Get all the scores of the method, so we can restart communication with the best one
            S, R = method_calculations(methods, net_env, [x[1] for x ∈ protocol_blacklist])
            # Get permutation of scores that puts the indices in order of best to worst 
            idxs = sortperm(S)
            # Iterate through methods until we find one that works, it will respond and verify...
            while !isempty(idxs)
                i = pop!(idxs)
                # Pop the next highest method, and sleep its inteval time
                # We don't want to ignore covertness because we are in recovery...
                sleep(R[i])
                # get a known host for the integrity check
                known_host = get_local_net_host(net_env[:queue], net_env[:src_ip], host_blacklist)

                # Update the method, and initialise it
                method = methods[i]
                method_kwargs = init(method, net_env)

                # Send recovery packet
                send_recovery_packet(method, last_integrity, known_host, net_env, method_kwargs)
                @debug "Attempting to recover with method" method=methods[i].name
                
                # Allow a larger timeout here, as the recovery process is a bit longer.
                if await_arp_beacon(net_env[:dest_ip], known_host, check_timeout*2)
                    # Success, we have recovered, so update the variables
                    recovery_timeouts = (time() - last_verification_time, packet_count - last_verification_packet_count)
                    last_verification_time = time()
                    last_verification_packet_count = packet_count
                    break # Don't need to try any more methods
                end
            end
            if isempty(idxs) # If we exhausted all methods, end communication
                error("Failed to recover with any method")
            end
            @info "Recovered with method" method=methods[current_method_index].name

            # Iterate through methods until we find one that works, it will respond and verify...
            recovery_mode = false
        end

        # Determine method to use, strip the penalties from the protocol blacklist, it doesn't need them
        # Give it the current method to discourage it from switching (using a 10% bonus to the score)
        method_index, time_interval = determine_method(methods, net_env, [x[1] for x ∈ protocol_blacklist], current_method_index)
        
        # If we have changed method, or are due an integrity check
        if method_index != current_method_index || packet_count % integrity_interval == 0
            # This label is jumped to later (for our final integrity check)
            @label verify
            # Get the current integrity, if we have used final padding, append it
            integrity = integrity_check(bits[chunk_pointer:pointer-1] * final_padding)
            # Get a known host for the integrity check
            known_host = get_local_net_host(net_env[:queue], net_env[:src_ip], host_blacklist)
            
            # Send the challenge
            send_method_change_packet(method, method_index, integrity ⊻ known_host, net_env, method_kwargs)
            
            # Switch methods
            method = methods[method_index]
            method_kwargs = init(method, net_env)
            current_method_index = method_index
            if packet_count % integrity_interval == 0
                @debug "Performing regular interval integrity check" interval=integrity_interval
            elseif method_index != current_method_index
                @debug "Switched method, performing integrity check" method=method.name interval=time_interval
                # open("../Testing-Data/timings/$(ARGS[3]).timings", "a") do io
                #     write(io, "SWITCH:$(method.name):$packet_count:$(time_ns())\n")
                # end
            else
                @debug "Final integrity check"
            end

            # Await the response
            if await_arp_beacon(net_env[:dest_ip], known_host, check_timeout) # Success
                # reset failures
                protocol_failures = 0
                @debug "Integrity check passed" method=method.name integrity known_host integrity ⊻ known_host
                # reset chunk pointer
                chunk_pointer = pointer
                # update last verified integrity (+ length)
                last_integrity = (chunk_pointer, integrity)
            else # Failure, resend chunk
                # Increment failures
                protocol_failures += 1
                # open("../Testing-Data/timings/$(ARGS[3]).timings", "a") do io
	            #     write(io, "FAIL:$(method.name):$(time_ns())\n")
                # end
                # If we have failed too many times, blacklist the protocol
                if protocol_failures == max_failures
                    push!(protocol_blacklist, (method_index, packet_count + penalty_size))
                    @info "Blacklisting protocol" protocol=method.name
                    protocol_failures = 0
                    # Enter recovery mode
                    recovery_mode = true
                    # open("../Testing-Data/timing/$(ARGS[3]).timings", "a") do io
                    # 	write(io, "BLACKLIST:$(method.name):$(time_ns())\n")
                    # end
            	end
                # Reset pointer to beginning of chunk
                pointer = chunk_pointer
                @warn "Failed integrity check" method=method.name integrity known_host integrity ⊻ known_host
                # Tell the target to discard the chunk, and send some data with it too
                pointer += send_discard_chunk_packet(method, bits, pointer, net_env, method_kwargs)
                # We aren't finished anymore (if we were before)
                finished = false
                final_padding = ""
            end
            # If we have finished, we can just exit here
            if finished
                break
            end
        end
        # Send payload packet
        if !finished && pointer+method.payload_size-1 > lastindex(bits)
            # For last part of payload, we will need to pad the remaining capacity
            payload = pad_packet_payload("0" * bits[pointer:lastindex(bits)], method.payload_size, _bits)
            @debug "Packet covert payload (Without MP)(FINAL)" payload=bits[pointer:lastindex(bits)] chunk_length=pointer-chunk_pointer total_sent=pointer
            payload_length = length(pointer:lastindex(bits))
            pointer += payload_length - 1
            # Save the final padding, so we can append it to the integrity check
            final_padding = payload[payload_length+1:end]
            # Set finished flag so we jump to verification stage
            finished = true
        elseif !finished
            # For all other packets, we can just send the payload
            payload = "0" * bits[pointer:pointer+method.payload_size-2]
            @debug "Packet covert payload (Without MP)" payload=bits[pointer:pointer+method.payload_size-2] chunk_length=pointer-chunk_pointer total_sent=pointer
            pointer += method.payload_size-1
        end
        # Send packet
        send_packet(method, net_env, payload, method_kwargs)
        # If that was the last packet, jump to verification stage
        if finished
            @debug "Payload sent, verifiying integrity"
            # This takes us to the `@label verify` line
            @goto verify
        end
        # Increment packet count
        packet_count += 1
        # Sleep for the time interval
        sleep(time_interval)
    end
    # open("../Testing-Data/timings/$(ARGS[3]).timings", "a") do io
    #     write(io, "END:$(packet_count):$(time_ns())\n")
    # end
    # Send sentinel packet to end communication
    send_sentinel_packet(method, net_env, method_kwargs)
    @debug "Endded communication via SENTINEL" via=method.name
end
