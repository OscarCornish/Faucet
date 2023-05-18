#=

    queue.jl

=#

"""
    errbuff_to_error(errbuf::Vector{UInt8})

Raise error with null terminated string, often returned by libpcap
"""
function errbuff_to_error(errbuf::Vector{UInt8})
    # Raise error with null terminated string
    error(String(errbuf[1:findfirst(==(0), errbuf) - 1]))
end 

"""
    pcap_lookupdev()::String

Get the default device
!!! Is a deprecated function, but is the simplest way to get the device
"""
function pcap_lookupdev()::String
    # Error is returned into errbuff
    errbuff = Vector{UInt8}(undef, PCAP_ERRBUF_SIZE)
    # Get device
    device = ccall(
        (:pcap_lookupdev, "libpcap"),
        Cstring,
        (Ptr{UInt8},),
        errbuff
    )
    if device == C_NULL
        errbuff_to_error(errbuff)
    end
    dev = unsafe_string(device)
    @debug "pcap_lookupdev() returned '$dev'"
    return dev
end

function get_dev()::String
    if length(ARGS) ≥ 2  
        @debug "Using device from command line" dev=ARGS[2]
        return ARGS[2]
    else
        return pcap_lookupdev()
    end
end

"""
    pcap_open_live(device::String, snapshot_len::Int64, promisc::Bool)::Ptr{Pcap}

Open a live pcap session, returning a handle to the session
"""
function pcap_open_live(device::String, snapshot_len::Int64, promisc::Bool)::Ptr{Pcap}
    # Error is returned into errbuff
    errbuff = Vector{UInt8}(undef, PCAP_ERRBUF_SIZE)
    # 1 is promisc, 0 isn't - so convert from Bool
    promisc = Int64(promisc)
    to_ms = 1000
    handle = ccall(
        (:pcap_open_live, "libpcap"),
        Ptr{Pcap},
        (Cstring, Int32, Int32, Int32, Ptr{UInt8}),
        device, snapshot_len, promisc, to_ms, errbuff
    )
    if handle == C_NULL
        errbuff_to_error(errbuff)
    end
    return handle
end

"""
    pcap_loop(p::Ptr{Pcap}, cnt::Int64, callback::Function, user::Union{Ptr{Nothing}, Ptr{UInt8}})

Loop through packets, calling callback on each packet
"""
function pcap_loop(p::Ptr{Pcap}, cnt::Int64, callback::Function, user::Union{Ptr{Nothing}, Ptr{UInt8}})::Nothing
    !hasmethod(callback, Tuple{Ptr{UInt8}, Ptr{Capture_header}, Ptr{UInt8}}) ? error("Invalid callback parameters") :
    cfunc = @cfunction($callback, Cvoid, (Ptr{UInt8}, Ptr{Capture_header}, Ptr{UInt8}))
    ccall(
        (:pcap_loop, "libpcap"),
        Int32,
        (Ptr{Pcap}, Int32, Ptr{Cvoid}, Ptr{Cuchar}),
        p, cnt, cfunc, user
    )
end

"""
    pcap_breakloop(pcap::Ptr{Pcap})::Nothing

Break out of pcap_loop
"""
function pcap_breakloop(pcap::Ptr{Pcap})::Nothing
    ccall((:pcap_breakloop, "libpcap"), Cvoid, (Ptr{Pcap},), pcap)
end

"""
    packet_from_pointer(p::Ptr{UInt8}, packet_size::Int32)::Layer{Ethernet_header}

Convert a pointer to a packet into a Layer{Ethernet_header} object, with all headers and payload
"""
function packet_from_pointer(p::Ptr{UInt8}, packet_size::Int32)::Layer{Ethernet_header}
    layer_index = 2
    offset = 0
    # Push layers here as we make them, then we can walk backwards and craft a full payload
    layers::Vector{Layer{<:Header}} = [Layer(Layer_type(layer_index), Ethernet_header(p), missing)]
    # Start at the lowest layer (Ethernet)
    node = HEADER_Ethernet
    # Don't exceed layer 3 (we +1 to make it 4, Transport, and we don't have any application layer protocols defined)
    # Would be an improvement to work this out by finding the depth of our HEADER_Ethernet tree...
    while layer_index ≤ 3
        prev_layer = layers[end]::Layer{<:Header}
        offset += getoffset(prev_layer)
        proto = getprotocol(prev_layer)
        # println("Packet context:", prev_layer, "\noffset:", offset, "\nproto:", proto)
        for child ∈ node.children
            if child.id == proto
                # println("Added child:", child)
                layer_index += 1
                node = child
                push!(layers, Layer(Layer_type(layer_index), child.type(p+offset), missing))
                # There is only 1 header per layer, so skip the search
                break
            end
        end
        if prev_layer.layer == Layer_type(layer_index)
            # End of tree
            break
        end
    end
    l = layers[end]::Layer{<:Header}
    offset += getoffset(l)

    # If there is a payload, read it into a vector
    payload_size = packet_size - offset
    if payload_size > 0
        payload = zeros(UInt8, payload_size)
        for i=1:payload_size
            payload[i] = Base.pointerref(p+offset+i, 1, 1)
        end
    else
        payload = Vector{UInt8}()
    end

    # Set the payload to the payload of the lowest layer
    l.payload = payload
    # Decrement layer index to walk backwards
    layer_index -= 1
    # Walk backwards through the layers, setting the payload of each layer to the layer above it, stopping at the link-layer (ETHERNET)
    while layer_index ≥ 2
        layer_index -= 1
        packet = layers[layer_index]::Layer{<:Header}
        packet.payload = l
        l = packet
    end
    # Return the lowest layer (ETHERNET)
    return l
end

"""
    get_callback(queue::CircularChannel{Packet})::Function

Get a callback function for pcap_loop, which will push packets to the queue
"""
function get_callback(queue)::Function
    function callback(::Ptr{UInt8}, header::Ptr{Capture_header}, packet::Ptr{UInt8})::Cvoid
        cap_hdr = unsafe_load(header)
        pkt = Packet(cap_hdr, packet_from_pointer(packet, cap_hdr.capture_length))
        put!(queue, pkt)
        sleep(0.001)
        return nothing
    end
    return callback
end 

"""
Get the local IP address of a device, if one is not given, assume default device
"""
function get_local_ip(device::String)::String
    match = get_ip_from_dev(device)
    if isnothing(match)
        error("Could not find IP address for device: ", device)
    end
    return match
end
get_local_ip() = get_local_ip(get_dev())

"""
    init_queue(device::String, bpf_filter_string::String="")::CircularChannel{Packet}

Given the device to open the queue on, return a CircularChannel{Packet} which will be filled with packets
"""
function init_queue(device::String=get_dev(); bpf_filter_string::String="")::CircularChannel{Packet}
    queue = CircularChannel{Packet}(5)
    handle = pcap_open_live(device, -1, true)
    # Set the filter if one is supplied
    if bpf_filter_string != ""
        program = Ref{bpf_prog}()
        pcap_compile(handle, program, bpf_filter_string, Int32(1), UInt32(0))
        # Add filter to pcap handle
        pcap_setfilter(handle, program)
        pcap_freecode(program)
    end
    close_pcap() = pcap_breakloop(handle)
    # Add a hook to close the pcap on exit, so the program exits cleanly
    atexit(close_pcap)
    # Create a fuction with the queue bound to it, so we don't have to deal with passing it every time
    callback = get_callback(queue)
    @debug "Creating pcap sniffer" device=device
    # Run the listener in a seperate thread
    #  we use errormonitor here so errors on this thread are sent to main thread
    errormonitor(Base.Threads.@spawn pcap_loop(handle, -1, callback, C_NULL))
    return queue
end
