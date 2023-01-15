#=

    Main

    Setup modules, including the files from inside the module folder

=#

include("constants.jl")
include("target.jl")

module Environment

    export init_queue, get_tcp_server, Packet

    include("environment/headers.jl")
    include("environment/query.jl")
    include("environment/queue.jl")

end

module CovertChannels

    export determine_method, covert_method, covert_methods, init, encode, decode

    include("covert_channels/microprotocols.jl")
    include("covert_channels/covert_channels.jl")
    
end

module Outbound

    export send_covert_payload

    include("outbound/generics.jl")
    include("outbound/environment.jl")
    include("outbound/packets.jl")

end

