using StaticArrays

struct Target
    ip::IPAddr
    covert_methods::Vector{String}
    AES_PSK::Vector{UInt8}
    AES_IV::Vector{UInt8}
    function Target(ip::IPv4Addr, covert_methods::Vector{String}, AES_PSK::SVector{16, UInt8}, AES_IV::SVector{16, UInt8})
        return new(ip, covert_methods, Vector{UInt8}(AES_PSK), Vector{UInt8}(AES_IV))
    end
end
function Target(ip::AbstractString, covert_methods::Vector{String}, AES_PSK::SVector{16, UInt8}, AES_IV::SVector{16, UInt8})
    return Target(IPv4Addr(ip), covert_methods, AES_PSK, AES_IV)
end

target = Target(
    "172.29.0.197",
    ["IPv4_identification", "TCP_ACK_Bounce"],
    SVector{16, UInt8}(0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00),
    SVector{16, UInt8}(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F)
)

"""
Target file structure:
ip: 'aaa.bbb.ccc.ddd'
covert_methods: ['method1', 'method2', ...]
AES_PSK: '000102030405060708090A0B0C0D0E0F'
AES_IV: '000102030405060708090A0B0C0D0E0F'
"""
