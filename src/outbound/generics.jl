using AES
using StaticArrays

# Generic functions for outbound packets

subnet_mask(nbits::Int64)::UInt32 = parse(UInt32, "1" ^ nbits * "0" ^ (32 - nbits), base=2)

is_address_local(ip::UInt32, source::UInt32, subnet_mask::UInt32)::Bool = (ip & subnet_mask) == (source & subnet_mask)
is_address_local(ip::UInt32, env::Dict{Symbol, Any})::Bool = is_address_local(ip, env[:src_ip], env[:subnet_mask])

enc(plaintext::Vector{UInt8})::Vector{UInt8} = encrypt(plaintext, AESCipher(;key_length=128, mode=AES.CBC, key=target.AES_PSK); iv=target.AES_IV).data
