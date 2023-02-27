using StaticArrays
import Base: string

to_bytes(x::UInt8)::SVector{1, UInt8} = [x]
to_bytes(x::UInt16)::SVector{2, UInt8} = unsafe_load(Ptr{SVector{2, UInt8}}(Base.unsafe_convert(Ptr{UInt16}, Ref(x))))
to_bytes(x::UInt32)::SVector{4, UInt8} = unsafe_load(Ptr{SVector{4, UInt8}}(Base.unsafe_convert(Ptr{UInt32}, Ref(x))))
to_bytes(x::UInt64)::SVector{8, UInt8} = unsafe_load(Ptr{SVector{8, UInt8}}(Base.unsafe_convert(Ptr{UInt64}, Ref(x))))

abstract type IPAddr end

struct IPv4Addr <: IPAddr
    host::UInt32
    function IPv4Addr(host::UInt32)
        return new(host)
    end
end
IPv4Addr(host::Vector{UInt8})::IPv4Addr = IPv4Addr(unsafe_load(Ptr{UInt32}(Base.unsafe_convert(Ptr{Vector{UInt8}}, reverse(host)))))
IPv4Addr(host::SVector{4, UInt8})::IPv4Addr = IPv4Addr(Vector{UInt8}(host))
IPv4Addr(host::AbstractString)::IPv4Addr = IPv4Addr(SVector{4, UInt8}(parse.(UInt8, split(host, "."), base=10)))

string(ip::IPv4Addr)::String = join(Int64.(reverse(to_bytes(ip.host))), ".")

mac(s::AbstractString)::NTuple{6, UInt8} = tuple(map(x->parse(UInt8, x, base=16), split(String(s), ':'))...)


@enum Transport_Type begin
    TCP = 0x6
    UDP = 0x11
end

@enum Network_Type begin
    IPv4 = 0x0800
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

const ip_a_regex = r"^(?<id>\d+): (?<dev_name>[a-zA-Z\d@]+): <[A-Z\-_ ,]+> mtu (?<mtu>\d+) .+\n\s+link\/(?<type>[a-z]+) (?<mac>[a-f\d:]{17}).+\n(?:(?:[\S ]*\n){0,3}    inet (?<addr>(?:\d{1,3}.){3}\d{1,3})\/(?<cidr>\d{1,2}).+\n.+|)"m
const ip_r_regex = r"(?<dest_ip>(?:\d{1,3}\.){3}\d{1,3})(?: via (?<gw>(?:\d{1,3}\.){3}\d{1,3})|) dev (?<if>\w+) src (?<src_ip>(?:\d{1,3}\.){3}\d{1,3})"
const ip_neigh_regex = r"(?<ip>(?:\d{1,3}\.){3}\d{1,3}) dev (?<if>\w+) lladdr (?<mac>[a-f\d:]{17})"
const ip_from_dev_regex = r"inet (?<ip>(?:\d{1,3}\.){3}\d{1,3})\/(?<cidr>\d{1,2})"
const mac_from_dev_regex = r"link\/(?<type>[a-z]+) (?<mac>[a-f\d:]{17})"

function ip_a_search(search_key::Symbol, search_val::Any, output_key::Union{Symbol, Nothing})::Any
    for match ∈ eachmatch(ip_a_regex, readchomp(`ip a`))
        @info "match[search_key] ($(match[search_key])) == search_val ($(search_val))"
        if match[search_key] == search_val
            if output_key === nothing
                return match
            else
                return match[output_key]
            end
        end
    end
    @warn "No match found for search key $(search_key) with value $(search_val)" output_key
    return nothing
end

function get_ip_from_dev(dev::String)::String
    output = readchomp(`ip a show dev $dev`)
    return match(ip_from_dev_regex, output)[:ip]
end

function get_mac_from_dev(dev::String)::NTuple
    output = readchomp(`ip a show dev $dev`)
    return mac(match(ip_a_regex, output)[:mac])
end

function get_dev_from_mac(mac::NTuple{6, UInt8})::String
    for match ∈ eachmatch(ip_a_regex, readchomp(`ip a`))
        if mac == mac(match[:mac])
            return match[:dev_name]
        end
    end
    return ""
end
