using StaticArrays
import Base: string
using CRC

to_bytes(x::UInt8)::SVector{1, UInt8} = [x]
to_bytes(x::UInt16)::SVector{2, UInt8} = reverse(unsafe_load(Ptr{SVector{2, UInt8}}(Base.unsafe_convert(Ptr{UInt16}, Ref(x)))))
to_bytes(x::UInt32)::SVector{4, UInt8} = reverse(unsafe_load(Ptr{SVector{4, UInt8}}(Base.unsafe_convert(Ptr{UInt32}, Ref(x)))))
to_bytes(x::UInt64)::SVector{8, UInt8} = reverse(unsafe_load(Ptr{SVector{8, UInt8}}(Base.unsafe_convert(Ptr{UInt64}, Ref(x)))))

abstract type IPAddr end

struct IPv4Addr <: IPAddr
    host::UInt32
    function IPv4Addr(host::UInt32)
        return new(host)
    end
end
IPv4Addr(host::Vector{UInt8})::IPv4Addr = IPv4Addr(unsafe_load(Ptr{UInt32}(Base.unsafe_convert(Ptr{Vector{UInt8}}, reverse(host)))))
IPv4Addr(host::SVector{4, UInt8})::IPv4Addr = IPv4Addr(Vector{UInt8}(host))
IPv4Addr(host::AbstractString)::IPv4Addr = IPv4Addr(SVector{4, UInt8}(reverse(parse.(UInt8, split(host, "."), base=10))))

_to_bytes(x::UInt8)::SVector{1, UInt8} = [x]
_to_bytes(x::UInt16)::SVector{2, UInt8} = unsafe_load(Ptr{SVector{2, UInt8}}(Base.unsafe_convert(Ptr{UInt16}, Ref(x))))
_to_bytes(x::UInt32)::SVector{4, UInt8} = unsafe_load(Ptr{SVector{4, UInt8}}(Base.unsafe_convert(Ptr{UInt32}, Ref(x))))
_to_bytes(x::UInt64)::SVector{8, UInt8} = unsafe_load(Ptr{SVector{8, UInt8}}(Base.unsafe_convert(Ptr{UInt64}, Ref(x))))

to_net(in::Unsigned)::Vector{UInt8} = _to_bytes(hton(in))
to_net(in::IPAddr)::Vector{UInt8} = _to_bytes(hton(in.host))
to_net(in::Vector{UInt8})::Vector{UInt8} = reverse(in)
to_net(in::SVector{4, UInt8})::Vector{UInt8} = reverse(in)

string(ip::IPv4Addr)::String = join(Int64.(reverse(to_bytes(ip.host))), ".")

mac(s::AbstractString)::NTuple{6, UInt8} = tuple(map(x->parse(UInt8, x, base=16), split(String(s), ':'))...)


@enum Transport_Type begin
    TCP = 0x6
    UDP = 0x11
end

@enum Network_Type begin
    IPv4 = 0x0800
    ARP  = 0x0806
end

@enum Link_Type begin
    Ethernet
end

@enum Layer_type begin
    physical = 1    # Ethernet (on the wire only)
    link = 2        # Ethernet
    network = 3     # IPv4
    transport = 4   # TCP
    application = 5 # HTTP
end

custom_crc8_poly(poly::UInt8) = CRC.spec(8, poly, poly, false, false, 0x00, 0xf4) # Mimic the CRC_8 spec, with a custom polynomial

"""
    integrity_check(chunk::bitstring)::UInt8

CRC8 of the chunk, padded to 8 bits
"""
function integrity_check(chunk::String)::UInt8
    padding = 8 - (length(chunk) % 8)
    chunk *= padding == 8 ? "" : "0"^padding
    @info "Integrity:" i=crc(CRC_8)([parse(UInt8, chunk[i:i+7], base=2) for i in 1:8:length(chunk)])
    return crc(CRC_8)([parse(UInt8, chunk[i:i+7], base=2) for i in 1:8:length(chunk)])
    # integrity ⊻ offset = active_host
    # offset can thus be calculated with offset = integrity ⊻ active_host 

    # Sender: (Receiving beacon)
    #  Knows:
    #  - active_host
    #  - integrity
    #  Can calculate offset
    #  integrity ⊻ active_host = offset

    # Then from (integrity ⊻ active_host) ⊻ integrity = active_host, we can calculate the active host
    # -> active_host_sent == active_host_recv to verify integrity


    # Recv: (Sending beacon)
    #  Knows:
    #   - integrity
    #   - offset (from method change)
    #  Can calculate active_host
    #  integrity ⊻ offset = active_host


end

const ip_address_regex = r"^(?<index>\d+): (?<iface>[\w\d]+)(?:@[\w\d]+)?: <(?<ifType>[A-Z,_]+)> mtu (?<mtu>\d+) [\w ]+ state (?<state>[A-Z]+) group default qlen (?<qlen>\d+)[\s ]+link\/ether (?<mac>(?:[a-f\d]{2}:){5}[a-f\d]{2}) brd (?<brd>[a-f\d:]{17}) [\w\- ]+[\s ]+inet (?<ip>(?:\d{1,3}.){3}\d{1,3})\/(?<subnet>\d+)"m
const ip_route_regex = r"^(?<dest_ip>(?:\d{1,3}.){3}\d{1,3}) (?:via (?<gw>(?:\d{1,3}.){3}\d{1,3}) )?dev (?<iface>[\w\d]+) src (?<src_ip>(?:\d{1,3}.){3}\d{1,3})"m
const ip_neigh_regex = r"^(?<ip>(?:\d{1,3}.){3}\d{1,3}) dev (?<iface>[\w\d]+) lladdr (?<mac>(?:[0-9a-f]{2}:){5}[0-9a-f]{2})"m
const ip_from_dev_regex = r"inet (?<ip>(?:\d{1,3}\.){3}\d{1,3})\/(?<cidr>\d{1,2})"
const mac_from_dev_regex = r"link\/(?<type>[a-z]+) (?<mac>[a-f\d:]{17})"

function ip_a_search(search_key::Symbol, search_val::Any, output_key::Union{Symbol, Nothing})::Any
    for match ∈ eachmatch(ip_address_regex, readchomp(`ip a`))
        #@info "match[search_key] ($(match[search_key])) == search_val ($(search_val))"
        if match[search_key] == search_val
            if output_key === nothing
                return match
            else
                return match[output_key]
            end
        end
    end
    #@warn "No match found for search key $(search_key) with value $(search_val)" output_key
    return nothing
end

function get_ip_from_dev(dev::String)::String
    output = readchomp(`ip a show dev $dev`)
    return match(ip_from_dev_regex, output)[:ip]
end

function get_mac_from_dev(dev::String)::NTuple
    output = readchomp(`ip a show dev $dev`)
    return mac(match(ip_address_regex, output)[:mac])
end

function get_dev_from_mac(mac::NTuple{6, UInt8})::String
    for match ∈ eachmatch(ip_address_regex, readchomp(`ip a`))
        if mac == mac(match[:mac])
            return match[:dev_name]
        end
    end
    return ""
end

function strip_padding(data::Vector{UInt8})::Vector{UInt8}
    padding = data[end]
    if data[end-padding+1:end] == [padding for i in 1:padding]
        return data[1:end-padding]
    else
        return data
    end
end

find_max_key(dict::Dict) = collect(keys(dict))[findmax(collect(values(dict)))[2]]
