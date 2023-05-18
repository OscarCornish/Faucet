#=

    Main

    Setup modules, including the files from inside the module folder

=#

# Convert to argument
PADDING_METHOD = :covert

include("CircularChannel.jl")
include("constants.jl")
include("utils.jl")
include("target.jl")

module Environment

    using .Main: Layer_type, get_ip_from_dev, IPv4Addr, _to_bytes, CircularChannel
    
    export init_queue

    include("environment/headers.jl")
    include("environment/query.jl")
    include("environment/bpf.jl")
    include("environment/queue.jl")
    include("environment/env_utils.jl")

end

module CovertChannels

    using .Main: Layer_type, IPv4, Network_Type, TCP, Transport_Type, CircularChannel, MINIMUM_CHANNEL_SIZE
    using ..Environment: Packet, get_tcp_server, get_queue_data, get_layer_stats, get_header, get_local_host_count

    export covert_methods

    include("covert_channels/covert_channels.jl")
    include("covert_channels/microprotocols.jl")
    
end

module Outbound

    using .Main: Target, target, IPv4Addr, Network_Type, Transport_Type, Link_Type, Ethernet, IPv4, TCP, UDP, ARP, to_bytes, ip_address_regex, ip_route_regex, ip_neigh_regex, mac, to_net, _to_bytes, integrity_check, PADDING_METHOD, remove_padding, CircularChannel
    using ..CovertChannels: craft_change_method_payload, craft_discard_chunk_payload, craft_sentinel_payload, craft_recovery_payload, method_calculations, determine_method, covert_method, init, encode
    using ..Environment: Packet, get_socket, sendto, await_arp_beacon, get_local_net_host, AF_PACKET, SOCK_RAW, ETH_P_ALL, IPPROTO_RAW

    include("outbound/environment.jl")
    include("outbound/packets.jl")

end

module Inbound

    using .Main: MINIMUM_CHANNEL_SIZE, target, integrity_check, IPv4Addr, PADDING_METHOD, remove_padding, CircularChannel
    using ..Environment: init_queue, local_bound_traffic, Packet, get_local_ip
    using ..CovertChannels: SENTINEL, DISCARD_CHUNK, couldContainMethod, decode, covert_method, extract_method
    using ..Outbound: ARP_Beacon

    include("inbound/listen.jl")

end
