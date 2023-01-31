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

    using .Main: IPAddr, IPv4Addr, Network_Type, Transport_Type, Layer_type, IPv4, TCP
    using ..Environment: Packet, get_tcp_server, TCP_SYN, get_queue_data, get_layer_stats

    export determine_method, covert_method, covert_methods, init, encode, decode

    include("covert_channels/covert_channels.jl")
    include("covert_channels/microprotocols.jl")
    
end

module Outbound

    using .Main: Target, target, IPAddr, IPv4Addr, Network_Type, Transport_Type, Link_Type, Ethernet, IPv4, TCP, UDP, to_bytes
    using ..CovertChannels: SENTINEL, craft_meta_payload
    using ..Environment: Packet

    export send_covert_payload, init_environment

    include("outbound/generics.jl")
    include("outbound/environment.jl")
    include("outbound/packets.jl")

end

