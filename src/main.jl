#=

    Main

    Setup modules, including the files from inside the module folder

=#

PADDING_METHOD = :covert # Convert to argument

include("constants.jl")
include("utils.jl")
include("target.jl")

module Environment

    using .Main: Layer_type, get_ip_from_dev, ip_a_search, IPv4Addr, IPAddr, _to_bytes, find_max_key
    export init_queue, get_tcp_server, Packet

    include("environment/headers.jl")
    include("environment/query.jl")
    include("environment/bpf.jl")
    include("environment/queue.jl")
    include("environment/env_utils.jl")

end

module CovertChannels

    using .Main: IPAddr, IPv4Addr, Network_Type, Transport_Type, Layer_type, IPv4, TCP, find_max_key
    using ..Environment: Packet, get_tcp_server, get_queue_data, get_layer_stats, get_header, get_local_host_count

    export determine_method, covert_method, covert_methods, init, encode, couldContainMethod, decode

    include("covert_channels/covert_channels.jl")
    include("covert_channels/microprotocols.jl")
    
end

module Outbound

    using .Main: Target, target, IPAddr, IPv4Addr, Network_Type, Transport_Type, Link_Type, Ethernet, IPv4, TCP, UDP, ARP, to_bytes, ip_address_regex, ip_route_regex, ip_neigh_regex, mac, to_net, _to_bytes, integrity_check, PADDING_METHOD, remove_padding
    using ..CovertChannels: craft_change_method_payload, craft_discard_chunk_payload, craft_sentinel_payload, craft_recovery_payload, method_calculations, determine_method, covert_method, init, encode
    using ..Environment: Packet, get_socket, sendto, await_arp_beacon, get_local_net_host, AF_PACKET, SOCK_RAW, ETH_P_ALL, IPPROTO_RAW

    export send_covert_payload, init_environment

    include("outbound/generics.jl")
    include("outbound/environment.jl")
    include("outbound/packets.jl")

end

module Inbou

    using .Main: MINIMUM_CHANNEL_SIZE, target, integrity_check, IPv4Addr, PADDING_METHOD, remove_padding
    using ..Environment: init_queue, local_bound_traffic, Packet, get_local_ip
    using ..CovertChannels: SENTINEL, DISCARD_CHUNK, couldContainMethod, decode, covert_method, extract_method
    using ..Outbound: ARP_Beacon

    export init_receiver

    include("inbound/listen.jl")

end
