using StaticArrays
import Base: string
using CRC

# Convert Unsigned integer to vector of UInt8
to_bytes(x::UInt8)::SVector{1, UInt8} = [x]
to_bytes(x::UInt16)::SVector{2, UInt8} = reverse(unsafe_load(Ptr{SVector{2, UInt8}}(Base.unsafe_convert(Ptr{UInt16}, Ref(x)))))
to_bytes(x::UInt32)::SVector{4, UInt8} = reverse(unsafe_load(Ptr{SVector{4, UInt8}}(Base.unsafe_convert(Ptr{UInt32}, Ref(x)))))
to_bytes(x::UInt64)::SVector{8, UInt8} = reverse(unsafe_load(Ptr{SVector{8, UInt8}}(Base.unsafe_convert(Ptr{UInt64}, Ref(x)))))

struct IPv4Addr
    host::UInt32
    function IPv4Addr(host::UInt32)
        return new(host)
    end
end
# For pretty printing
string(ip::IPv4Addr)::String = join(Int64.(reverse(to_bytes(ip.host))), ".")

IPv4Addr(host::Vector{UInt8})::IPv4Addr = IPv4Addr(unsafe_load(Ptr{UInt32}(Base.unsafe_convert(Ptr{Vector{UInt8}}, reverse(host)))))
IPv4Addr(host::SVector{4, UInt8})::IPv4Addr = IPv4Addr(Vector{UInt8}(host))
IPv4Addr(host::AbstractString)::IPv4Addr = IPv4Addr(SVector{4, UInt8}(reverse(parse.(UInt8, split(host, "."), base=10))))

# Convert but keep byte order
_to_bytes(x::UInt8)::SVector{1, UInt8} = [x]
_to_bytes(x::UInt16)::SVector{2, UInt8} = unsafe_load(Ptr{SVector{2, UInt8}}(Base.unsafe_convert(Ptr{UInt16}, Ref(x))))
_to_bytes(x::UInt32)::SVector{4, UInt8} = unsafe_load(Ptr{SVector{4, UInt8}}(Base.unsafe_convert(Ptr{UInt32}, Ref(x))))
_to_bytes(x::UInt64)::SVector{8, UInt8} = unsafe_load(Ptr{SVector{8, UInt8}}(Base.unsafe_convert(Ptr{UInt64}, Ref(x))))

# Convert to network byte order
to_net(in::Unsigned)::Vector{UInt8} = _to_bytes(hton(in))
to_net(in::IPv4Addr)::Vector{UInt8} = _to_bytes(hton(in.host))
to_net(in::Vector{UInt8})::Vector{UInt8} = reverse(in)
to_net(in::SVector{4, UInt8})::Vector{UInt8} = reverse(in)

# Parse a mac string into a UInt8 tuple
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

```markdown
    Integrity: Known by both hosts
    Known_host: Known by challenger
    
    offset = integrity ⊻ known_host

    Challenger sends offset, responder returns `offset ⊻ integrity`
```
This implementation is CRC8 based, but just has to be deterministic.
"""
function integrity_check(chunk::String)::UInt8
    padding = 8 - (length(chunk) % 8)
    # Payload may not be byte aligned, so pad it
    chunk *= padding == 8 ? "" : "0"^padding
    return crc(CRC_8)([parse(UInt8, chunk[i:i+7], base=2) for i in 1:8:length(chunk)])
end

"""
    remove_padding(payload::bitstring, method::Symbol=PADDING_METHOD)::bitstring

    Removes the padding applied by [`pad_transmission`](@ref) from the payload.
"""
function remove_padding(payload::String, method::Symbol=PADDING_METHOD)::String
    if method == :short
        return rstrip(payload, '0')[1:end-1]
    elseif method == :covert
        for i = length(payload):-1:1
            if i % 128 == 0
                bitlen = lstrip(bitstring(Int64(i/128)), '0')
                if length(payload) - i >= length(bitlen)
                    if payload[i+1:i+length(bitlen)] == bitlen
                        payload = payload[1:i]
                        return payload
                    end
                end
            end
        end
        error("Incorrect padding")
    else
        error("Padding method $method not supported")
    end
end

# Regular expressions to parse these command's outputs
const ip_address_regex = r"^(?<index>\d+): (?<iface>[\w\d]+)(?:@[\w\d]+)?: <(?<ifType>[A-Z,_]+)> mtu (?<mtu>\d+) [\w ]+ state (?<state>[A-Z]+) group default qlen (?<qlen>\d+)[\s ]+link\/ether (?<mac>(?:[a-f\d]{2}:){5}[a-f\d]{2}) brd (?<brd>[a-f\d:]{17}) [\w\- ]+[\s ]+inet (?<ip>(?:\d{1,3}.){3}\d{1,3})\/(?<subnet>\d+)"m
const ip_route_regex = r"^(?<dest_ip>(?:\d{1,3}.){3}\d{1,3}) (?:via (?<gw>(?:\d{1,3}.){3}\d{1,3}) )?dev (?<iface>[\w\d]+) src (?<src_ip>(?:\d{1,3}.){3}\d{1,3})"m
const ip_neigh_regex = r"^(?<ip>(?:\d{1,3}.){3}\d{1,3}) dev (?<iface>[\w\d]+) lladdr (?<mac>(?:[0-9a-f]{2}:){5}[0-9a-f]{2})"m
const ip_from_dev_regex = r"inet (?<ip>(?:\d{1,3}\.){3}\d{1,3})\/(?<cidr>\d{1,2})"
const mac_from_dev_regex = r"link\/(?<type>[a-z]+) (?<mac>[a-f\d:]{17})"

# Get the interface for the given ip
function get_ip_from_dev(dev::String)::String
    output = readchomp(`ip a show dev $dev`)
    return match(ip_from_dev_regex, output)[:ip]
end
        