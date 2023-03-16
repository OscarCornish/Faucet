#=

    Covert channels

=#

struct covert_method{Symbol}
    name::String
    layer::Layer_type
    type::String # What packet type are we aiming for?
    covertness::Int8 # 1 - 10
    payload_size::Int64 # bits / packet
    covert_method(name::String, layer::Layer_type, type::String, covertness::Int64, payload_size::Int64)::covert_method{Symbol} = new{Symbol(name)}(name, layer, type, Int8(covertness), payload_size)
end

"""
    craft_meta_payload(payload, capacity)::String
Pads payload with random bits to reach capacity
"""
function craft_meta_payload(payload::String, capacity::Int64)::String
    @debug "Crafting meta payload from string" payload capacity
    return payload * join([rand(("1","0")) for i ∈ 1:(capacity - length(payload))])
end

function craft_meta_payload(payload::Unsigned, capacity::Int64)::String
    return craft_meta_payload(bitstring(payload)[end-MINIMUM_CHANNEL_SIZE+1:end], capacity)
end

"""
    craft_meta_payload(method_index, capacity)::String
Given index of covert method, craft a meta payload to tell the target which method to use
"""
function craft_meta_payload(method_index::Int64, capacity::Int64)::String
    payload = "1" * bitstring(UInt8(method_index))[end-2:end]
    return craft_meta_payload(payload, capacity)
end

#=
    TCP_ACK_Bounce abuses the TCP handshake,
    by spoofing the source to the destination and sending a request to a server,
    the server responds with an ACK# of the original packets ISN+1,
    the reciver can then -1 and decode using a predefined technique
    - Requires a TCP server (could be derived from env_q?)

    - Target IP (In env)
    - Target Mac (in env)
    - TCP Server Mac (or first gw mac)
    - TCP Server IP
    - TCP Server Port

=#

tcp_ack_bounce::covert_method{:TCP_ACK_Bounce} = covert_method(
    "TCP_ACK_Bounce",
    Layer_type(4), # transport
    "TCP_header",
    5,
    32 # 4 bytes / packet
)

# Init function for TCP_ACK_Bounce
function init(::covert_method{:TCP_ACK_Bounce}, net_env::Dict{Symbol, Any})::Dict{Symbol, Any}
    dest_mac, dest_ip, dport = get_tcp_server(net_env[:queue])
    return Dict{Symbol, Any}(
        :payload => Vector{UInt8}("Covert packet!"), # Obviously not a real payload
        :env => net_env,
        :network_type => IPv4::Network_Type,
        :transport_type => TCP::Transport_Type,
        :EtherKWargs => Dict{Symbol, Any}(
            :source_mac => net_env[:dest_first_hop_mac],
            :dest_mac => dest_mac
        ),
        :NetworkKwargs => Dict{Symbol, Any}(
            :source_ip => net_env[:dest_ip].host,
            :dest_ip => dest_ip
        ),
        :TransportKwargs => Dict{Symbol, Any}(
            :flags => TCP_SYN::UInt16,
            :dport => dport
        )
    )
end

# Encode function for TCP_ACK_Bounce
function encode(::covert_method{:TCP_ACK_Bounce}, payload::UInt32; template::Dict{Symbol, Any})::Dict{Symbol, Any} 
    @debug "Encoding packet {TCP_ACK_Bounce}" payload
    template[:TransportKwargs][:seq] = payload - 0x1
    return template
end
encode(m::covert_method{:TCP_ACK_Bounce}, payload::String; template::Dict{Symbol, Any})::Dict{Symbol, Any} = encode(m, parse(UInt32, payload, base=2); template=template)

# Decode function for TCP_ACK_Bounce
decode(::covert_method{:TCP_ACK_Bounce}, pkt::Packet)::UInt16 = pkt.payload.payload.payload.header.ack_num

#=
    IPv4_identification utilises the 'random' identification header,
    this can be replaced with encrypted (so essentially random) data.
=#

ipv4_identifaction::covert_method{:IPv4_Identification} = covert_method(
    "IPv4_Identification",
    Layer_type(3), # network
    "IPv4_header",
    8,
    16, # 2 bytes / packet
)

# Init function for IPv4_Identification
function init(::covert_method{:IPv4_Identification}, net_env::Dict{Symbol, Any})::Dict{Symbol, Any}
    target_mac, target_ip = net_env[:dest_first_hop_mac], net_env[:dest_ip].host
    return Dict{Symbol, Any}(
        :payload => Vector{UInt8}("Covert packet!"), # Obviously not a real payload
        :env => net_env,
        :network_type => IPv4::Network_Type,
        :transport_type => TCP::Transport_Type,
        :EtherKWargs => Dict{Symbol, Any}(
            :dest_mac => target_mac,
        ),
        :NetworkKwargs => Dict{Symbol, Any}(
            :dest_ip => target_ip,
        )
    )
end

# Encode function for IPv4_Identification
function encode(::covert_method{:IPv4_Identification}, payload::UInt16; template::Dict{Symbol, Any})::Dict{Symbol, Any}
    @debug "Encoding packet {IPv4_Identification}" payload
    template[:NetworkKwargs][:identification] = payload
    return template
end
encode(m::covert_method{:IPv4_Identification}, payload::String; template::Dict{Symbol, Any})::Dict{Symbol, Any} = encode(m, parse(UInt16, payload, base=2); template=template)

# Decode function for IPv4_Identification
decode(::covert_method{:IPv4_Identification}, pkt::Packet)::UInt32 = pkt.payload.payload.header.id


covert_methods = Vector{covert_method}([
    ipv4_identifaction,
    tcp_ack_bounce
])

"""
    determine_method(covert_methods::Vector{covert_method})::Tuple{covert_method, Int64}

Determine which method is most suited to the current network environment, taking a list of methods and the network environment
```
Parameters:
    - covert_methods : List of covert methods

Returns:
    - The method that is most likely to be used
    - The intervals at which covert packets should be sent
```
# Notes
```text
Uses a scoring algorithm:
    - v : Number of packets with valid headers for this method
    - c : Covertness of the method, higher is better
    - s : Payload size of the method, higher is better
score : (v * c) + s
```
"""
function determine_method(covert_methods::Vector{covert_method}, env::Dict{Symbol, Any})::Tuple{Int64, Int64}
    # Get the queue data
    q = get_queue_data(env[:queue])

    if isempty(q)
        @error "No packets in queue, cannot determine method" q
        #error("Empty queue")
    end
    
    #@warn "Hardcoded response to determine_method"
    return 1, 1

    layer_stats = [get_layer_stats(q, Layer_type(i)) for i ∈ 2:4]

    scores = Vector{Pair{covert_method, Int64}}()

    for method ∈ covert_methods
        v = 0
        for layer in layer_stats
            if method.layer ∈ keys(layer)
                v = layer[method.layer] / +(collect(values(layer))...)
            end
        end
        c = method.covertness
        s = method.payload_size
        push!(scores, method => (v * c) + s)
    end

    time_interval = abs(first(q).Capture_header.timestamp - last(q).Capture_header.timestamp)
    packets_per_second = length(q) / time_interval
    target_packets_per_second = packets_per_second * PACKET_SEND_RATE
    target_interval = round(Int64, 1 / target_packets_per_second)

    # Sort scores by second value in pair (score) and return highest
    highest = first(sort(scores, by=x->x[2], rev=true))[1]

    # Pretty sure this should be the index of the highest score method, not the method itself
    return highest[1], target_interval
end

