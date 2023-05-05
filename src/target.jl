using StaticArrays

# This struct is the basis of our "Agreement"
struct Target
    # The IP of the target (receiver)
    ip::IPv4Addr
    # The methods to use
    covert_methods::Vector{String}
    # The AES PSK and IV
    AES_PSK::Vector{UInt8}
    AES_IV::Vector{UInt8}
    function Target(ip::IPv4Addr, covert_methods::Vector{String}, AES_PSK::SVector{16, UInt8}, AES_IV::SVector{16, UInt8})
        return new(ip, covert_methods, Vector{UInt8}(AES_PSK), Vector{UInt8}(AES_IV))
    end
end
function Target(ip::AbstractString, covert_methods::Vector{String}, AES_PSK::SVector{16, UInt8}, AES_IV::SVector{16, UInt8})
    return Target(IPv4Addr(ip), covert_methods, AES_PSK, AES_IV)
end

chunk(s::AbstractString, n::Int)::Vector{AbstractString} = [s[i:min(i + n - 1, end)] for i=1:n:length(s)]

"""
Parse target from file structure to Target struct
```
Target file structure:
ip: 'aaa.bbb.ccc.ddd'
covert_methods: ['method1', 'method2', ...]
AES_PSK: '000102030405060708090A0B0C0D0E0F'
AES_IV: '000102030405060708090A0B0C0D0E0F'
```
"""
function parse_target_file(file::AbstractString)::Target
    target = Dict{String, String}([attr => value for (attr, value) ∈ split.(split(readchomp(file), "\n"), ": ")])
    # Check all required keys are present, any others will be ignored
    if all(["ip", "covert_methods", "AES_PSK", "AES_IV"] .∉ Ref(keys(target)))
        @error "Invalid arguments" keys(target)
        throw(ArgumentError("Target file must contain ip, covert_methods, AES_PSK, and AES_IV"))
    end

    # extract the values from the text form, using the ' delimiter
    ip = split(target["ip"], "'")[2]
    covert_methods = String.(split(split(split(target["covert_methods"], "['")[2], "']")[1], "', '"))
    AES_PSK = SVector{16, UInt8}(parse.(UInt8, chunk(split(target["AES_PSK"], "'")[2], 2); base=16))
    AES_IV = SVector{16, UInt8}(parse.(UInt8, chunk(split(target["AES_IV"], "'")[2], 2); base=16))
    
    # Return the target
    return Target(ip, covert_methods, AES_PSK, AES_IV)
end

# Get the target file from the arguments
if length(ARGS) > 0
    target = parse_target_file(ARGS[1])
else
    error("No target file provided")
end

# Example target file
"""
ip: '10.20.30.2'
covert_methods: ['IPv4_identification', 'TCP_ACK_Bounce']
AES_PSK: '0F0E0D0C0B0A09080706050403020100'
AES_IV: '000102030405060708090A0B0C0D0E0F'
"""
