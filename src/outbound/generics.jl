using AES

# Generic functions for outbound packets

mac(s::AbstractString)::NTuple{6, UInt8} = tuple(map(x->parse(UInt8, x, base=16), split(String(s), ':'))...)
subnet_mask(nbits::Int64)::UInt32 = parse(UInt32, "1" ^ nbits * "0" ^ (32 - nbits), base=2)

is_address_local(ip::UInt32, source::UInt32, subnet_mask::UInt32)::Bool = (ip & subnet_mask) == (source & subnet_mask)
is_address_local(ip::UInt32, env::Dict{Symbol, Any})::Bool = is_address_local(ip, env[:src_ip], env[:subnet_mask])

to_net(in::Unsigned)::Vector{UInt8} = to_bytes(hton(in))
to_net(in::IPAddr)::Vector{UInt8} = to_bytes(hton(in.host))
to_net(in::Vector{UInt8})::Vector{UInt8} = reverse(in)

const ip_a_regex = r"^(?<id>\d+): (?<dev_name>[a-zA-Z\d@]+): <[A-Z\-_ ,]+> mtu (?<mtu>\d+) .+\n\s+link\/(?<type>[a-z]+) (?<mac>[a-f\d:]{17}).+\n(?:(?:[\S ]*\n){0,3}    inet (?<addr>(?:\d{1,3}.){3}\d{1,3})\/(?<cidr>\d{1,2}).+\n.+|)"m
const ip_r_regex = r"(?<dest_ip>(?:\d{1,3}\.){3}\d{1,3})(?: via (?<gw>(?:\d{1,3}\.){3}\d{1,3})|) dev (?<if>\w+) src (?<src_ip>(?:\d{1,3}\.){3}\d{1,3})"
const ip_neigh_regex = r"(?<ip>(?:\d{1,3}\.){3}\d{1,3}) dev (?<if>\w+) lladdr (?<mac>[a-f\d:]{17})"

enc(plaintext::Vector{UInt8})::Vector{UInt8} = encrypt(plaintext, AESCipher(;key_length=128, mode=AES.CBC, key=target.AES_PSK); iv=target.AES_IV).data
