#=

    Main

    Setup modules, including the files from inside the module folder

=#

include("constants.jl")
include("utils.jl")
include("target.jl")

#run(Cmd(["ping", "-c", "1", string(target.ip)]))

module Environment

    using .Main: Layer_type, get_ip_from_dev, ip_a_search
    export init_queue, get_tcp_server, Packet

    include("environment/headers.jl")
    include("environment/query.jl")
    include("environment/bfp.jl")
    include("environment/queue.jl")
    include("environment/env_utils.jl")

end

module CovertChannels

    using .Main: IPAddr, IPv4Addr, Network_Type, Transport_Type, Layer_type, IPv4, TCP
    using ..Environment: Packet, get_tcp_server, TCP_SYN, get_queue_data, get_layer_stats

    export determine_method, covert_method, covert_methods, init, encode, decode

    include("covert_channels/covert_channels.jl")
    include("covert_channels/microprotocols.jl")
    
end

module Outbound

    using .Main: Target, target, IPAddr, IPv4Addr, Network_Type, Transport_Type, Link_Type, Ethernet, IPv4, TCP, UDP, to_bytes, ip_a_regex, ip_r_regex, ip_neigh_regex, mac
    using ..CovertChannels: craft_change_method_payload, craft_discard_chunk_payload, craft_sentinel_payload
    using ..Environment: Packet, get_socket, sendto

    export send_covert_payload, init_environment

    include("outbound/generics.jl")
    include("outbound/environment.jl")
    include("outbound/packets.jl")

end

module Inbound

    using .Main: MINIMUM_CHANNEL_SIZE, target
    using ..Environment: init_queue, local_bound_traffic, Packet, get_local_ip
    using ..CovertChannels: SENTINEL, decode, covert_method, extract_method
    using ..Outbound: ARP_Beacon

    export init_receiver

    include("inbound/listen.jl")

end
