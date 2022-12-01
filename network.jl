# Requires the packet structs defined in headers.jl

include("headers.jl")

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

sniff(callback)