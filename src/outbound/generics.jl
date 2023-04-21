using AES
using StaticArrays

# Generic functions for outbound packets

subnet_mask(nbits::Int64)::UInt32 = parse(UInt32, "1" ^ nbits * "0" ^ (32 - nbits), base=2)

is_address_local(ip::UInt32, source::UInt32, subnet_mask::UInt32)::Bool = (ip & subnet_mask) == (source & subnet_mask)
is_address_local(ip::UInt32, env::Dict{Symbol, Any})::Bool = is_address_local(ip, env[:src_ip], env[:subnet_mask])

_to_bytes(x::UInt8)::SVector{1, UInt8} = [x]
_to_bytes(x::UInt16)::SVector{2, UInt8} = unsafe_load(Ptr{SVector{2, UInt8}}(Base.unsafe_convert(Ptr{UInt16}, Ref(x))))
_to_bytes(x::UInt32)::SVector{4, UInt8} = unsafe_load(Ptr{SVector{4, UInt8}}(Base.unsafe_convert(Ptr{UInt32}, Ref(x))))
_to_bytes(x::UInt64)::SVector{8, UInt8} = unsafe_load(Ptr{SVector{8, UInt8}}(Base.unsafe_convert(Ptr{UInt64}, Ref(x))))

to_net(in::Unsigned)::Vector{UInt8} = _to_bytes(hton(in))
to_net(in::IPAddr)::Vector{UInt8} = _to_bytes(hton(in.host))
to_net(in::Vector{UInt8})::Vector{UInt8} = reverse(in)

enc(plaintext::Vector{UInt8})::Vector{UInt8} = encrypt(plaintext, AESCipher(;key_length=128, mode=AES.CBC, key=target.AES_PSK); iv=target.AES_IV).data
