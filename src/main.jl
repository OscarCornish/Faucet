#=

    Main

    Setup modules, including the files from inside the module folder

=#

include("constants.jl")
include("utils.jl")
include("target.jl")

module Environment

    using .Main: Layer_type
    export init_queue, get_tcp_server, Packet

    include("environment/headers.jl")
    include("environment/query.jl")
    include("environment/queue.jl")

end

module CovertChannels

    using .Main: IPAddr, IPv4Addr, Network_Type, Transport_Type, Layer_type
    using ..Environment: Packet, get_tcp_server

    export determine_method, covert_method, covert_methods, init, encode, decode

    include("covert_channels/covert_channels.jl")
    include("covert_channels/microprotocols.jl")
    
end

module Outbound

    using .Main: Target, target, IPAddr, IPv4Addr, Network_Type, Transport_Type, Link_Type
    using ..Environment: Packet

    export send_covert_payload, init_environment

    include("outbound/generics.jl")
    include("outbound/environment.jl")
    include("outbound/packets.jl")

end

