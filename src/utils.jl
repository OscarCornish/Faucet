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