# Requires the packet structs defined in headers.jl

include("environment.jl")

#=
    Utility functions
=#

# libpcap errors come in a null terminated string in a buffer
function errbuff_to_error(errbuf::Vector{UInt8})
    # Raise error with null terminated string
    error(String(errbuf[1:findfirst(==(0), errbuf) - 1]))
end

#=
    C Function wrappers
=#

# pcap_open_live(device, snapshot length (-1 for inf), promisc)
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

function pcap_loop(p::Ptr{Pcap}, cnt::Int64, callback::Function, user::Union{Ptr{Nothing}, Ptr{UInt8}})
    !hasmethod(callback, Tuple{Ptr{UInt8}, Ptr{Capture_header}, Ptr{UInt8}}) ? error("Invalid callback parameters") :
    cfunc = @cfunction($callback, Cvoid, (Ptr{UInt8}, Ptr{Capture_header}, Ptr{UInt8}))
    ccall(
        (:pcap_loop, "libpcap"),
        Int32,
        (Ptr{Pcap}, Int32, Ptr{Cvoid}, Ptr{Cuchar}),
        p, cnt, cfunc, user
    )
end

#handle = pcap_open_live(pcap_lookupdev(), -1, true)
handle = pcap_open_live("wlo1", -1, true)

function pcap_breakloop(pcap::Ptr{Pcap})::Nothing
    ccall((:pcap_breakloop, "libpcap"), Cvoid, (Ptr{Pcap},), pcap)
end

# Add hook to close pcap on exit
close_pcap() = pcap_breakloop(handle)
atexit(close_pcap)

function sniff(callback::Function)::Nothing
    pcap_loop(handle, -1, callback, C_NULL)
end

# @debug macro does not work in callback context
function packet_from_pointer(p::Ptr{UInt8}, packet_size::Int32)::Layer{Ethernet_header}
    layer_index = 2
    offset = 0
    layers::Vector{Layer{<:Header}} = [Layer(Layer_type(layer_index), Ethernet_header(p), missing)] # Push layers here as we make them, then replace the missing backwards...
    node = Ethernet
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
                break
            end
        end
        if prev_layer.layer == Layer_type(layer_index)
            # End of tree
            @debug "End of packet tree:" layer=Layer_type(layer_index) protocol_code=proto node
            break
        end
    end
    l = layers[end]::Layer{<:Header}
    offset += getoffset(l)
    payload_size = packet_size - offset
    if payload_size > 0
        payload = zeros(UInt8, payload_size)
        for i=1:payload_size
            payload[i] = Base.pointerref(p+offset+i, 1, 1)
        end
    else
        payload = Vector{UInt8}()
    end
    # println("Payload size: ", payload_size)
    l.payload = payload
    layer_index -= 1
    while layer_index ≥ 2
        layer_index -= 1
        packet = layers[layer_index]::Layer{<:Header} # Minus 1 because our layers start at 2
        packet.payload = l
        l = packet
    end
    return l
end    

# Callback for packet_from_pointer

function callback(::Ptr{UInt8}, header::Ptr{Capture_header}, packet::Ptr{UInt8})::Cvoid
    cap_hdr = unsafe_load(header)
    println("\n")
    packet = Packet(cap_hdr, packet_from_pointer(packet, cap_hdr.length))
    dump(packet)
    exit(1) 
end

q = Channel{Packet}(ENVIRONMENT_QUEUE_SIZE)

function q_push(::Ptr{UInt8}, header::Ptr{Capture_header}, packet::Ptr{UInt8})::Cvoid
    #print("*")
    cap_hdr = unsafe_load(header)
    p = Packet(cap_hdr, packet_from_pointer(packet, cap_hdr.length))
    if q.n_avail_items == ENVIRONMENT_QUEUE_SIZE
        take!(q)
    end
    put!(q, p)
    return nothing
end

#=

    Header debugging callback

#

function callback(user::Ptr{UInt8}, header::Ptr{Capture_header}, packet::Ptr{UInt8})::Cvoid
    cap_hdr = unsafe_load(header)
    eth_hdr = Ethernet_header(packet)
    if eth_hdr.type == 0x0008
        offset = sizeof(Ethernet_header)
        ip4_hdr = IPv4_header(packet)
        if ip4_hdr.protocol == 0x06
            offset = offset + (ip4_hdr.ihl * 4)
            tcp_hdr = TCP_header(packet, offset)
            @info "Pointers" packet offset packet+offset
            println("")
            dump(cap_hdr)
            println("")
            dump(eth_hdr)
            println("")
            dump(ip4_hdr)
            println("")
            dump(tcp_hdr)
            exit(1)
        end
    end
end

=#

@async sniff(q_push)
dump_queue(q)
println("Main thread done...")