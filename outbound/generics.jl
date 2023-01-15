using StaticArrays

# Generic functions for outbound packets

mac(s::AbstractString)::NTuple{6, UInt8} = tuple(map(x->parse(UInt8, x, base=16), split(String(s), ':'))...)
subnet_mask(nbits::Int64)::UInt32 = parse(UInt32, "1" ^ nbits * "0" ^ (32 - nbits), base=2)

is_address_local(ip::UInt32, source::UInt32, subnet_mask::UInt32)::Bool = (ip & subnet_mask) == (source & subnet_mask)
is_address_local(ip::UInt32, env::Dict{Symbol, Any})::Bool = is_address_local(ip, env[:src_ip], env[:subnet_mask])

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
IPv4Addr(host::SVector{4, UInt8})::IPv4Addr = IPv4Addr(unsafe_load(Ptr{UInt32}(Base.unsafe_convert(Ptr{SVector{4, UInt8}}, reverse(host)))))
IPv4Addr(host::AbstractString)::IPv4Addr = IPv4Addr(SVector{4}(parse.(UInt8, split(host, "."), base=10)))

string(ip::IPv4Addr)::String = join(parse.(Int64, to_bytes(ip.host)), ".")

to_net(in::Unsigned)::Vector{UInt8} = to_bytes(hton(in))
to_net(in::IPAddr)::Vector{UInt8} = to_bytes(hton(in.host))
to_net(in::Vector{UInt8})::Vector{UInt8} = reverse(in)

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

const ip_a_regex = r"^(?<id>\d+): (?<dev_name>[a-zA-Z\d@]+): <[A-Z\-_ ,]+> mtu (?<mtu>\d+) .+\n\s+link\/(?<type>[a-z]+) (?<mac>[a-f\d:]{17}).+\n(?:(?:[\S ]*\n){0,3}    inet (?<addr>(?:\d{1,3}.){3}\d{1,3})\/(?<cidr>\d{1,2}).+\n.+|)"m
const ip_r_regex = r"(?<dest_ip>(?:\d{1,3}\.){3}\d{1,3})(?: via (?<gw>(?:\d{1,3}\.){3}\d{1,3})|) dev (?<if>\w+) src (?<src_ip>(?:\d{1,3}\.){3}\d{1,3})"
const ip_neigh_regex = r"(?<ip>(?:\d{1,3}\.){3}\d{1,3}) dev (?<if>\w+) lladdr (?<mac>[a-f\d:]{17})"
