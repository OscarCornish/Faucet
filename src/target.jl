using StaticArrays

struct Target
    ip::IPAddr
    covert_methods::Vector{String}
    covert_options::Dict{String, Any}
    AES_PSK::Vector{UInt8}
    AES_IV::Vector{UInt8}
    function Target(ip::IPv4Addr, covert_methods::Vector{String}, covert_options::Dict{String, Any}, AES_PSK::SVector{16, UInt8}, AES_IV::SVector{16, UInt8})
        return new(ip, covert_methods, covert_options, Vector{UInt8}(AES_PSK), Vector{UInt8}(AES_IV))
    end
end
function Target(ip::AbstractString, covert_methods::Vector{String}, covert_options::Dict{String, Any}, AES_PSK::SVector{16, UInt8}, AES_IV::SVector{16, UInt8})
    return Target(IPv4Addr(ip), covert_methods, covert_options, AES_PSK, AES_IV)
end

# TODO: Remove options from target, the method can be determined using the micro protocols
#           however a port still must be specified

target = Target(
    "192.168.0.1",
    ["TCP_ACK_Bounce", "IPv4_identification"],
    Dict{String, Any}(
        "TCP_ACK_Bounce" => Dict{String, Any}(
            "listen_port" => 12873
        ),
        "IPv4_identification" => Dict{String, Any}(
            "listen_port" => 12874
        )
    ),
    SVector{16, UInt8}(0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00),
    SVector{16, UInt8}(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F)
)