#=

    covert_channel.jl

    Functions relating to actual covert communication:
     - Sending covert packets
     - Crafting covert packets
     - Micro protocols

=#

@debug "covert_channel: Loading..."

using AES

include("constants.jl")

#=

    Covert channel definitions:

=#

const CIPHER = AESCipher(;key_length=128, mode=AES.CBC, key=AES128Key(AES_KEY))
enc(plaintext::Vector{UInt8})::Vector{UInt8} = encrypt(plaintext, CIPHER; iv=AES_IV).data

# function create_15bit_payload(raw_payload::Vector{UInt8})::Vector{UInt16}
#     bits = *(bitstring.(enc(raw_payload))...)
#     padding = "0" ^ round(Int64, (1 - (length(bits) % 15) / 15) * 15)
#     bits *= padding
#     payload = [parse(UInt16, bits[i:min(i+14, end)], base=2) for i in 1:15:length(bits)]
#     return payload
# end

struct covert_method
    name::String
    layer::Layer_type
    type::String # What packet type are we aiming for?
    covertness::Int8 # 1 - 10
    payload_size::Int64 # bits / packet
    encode_functions::Tuple{Function, Function}
    decode_function::Function
end

function craft_meta_payload(payload::String, capacity::Int64)::String
    return payload * join([rand(("1","0")) for i ∈ 1:(capacity - length(payload))])
end

function craft_meta_payload(payload::Unsigned, capacity::Int64)::String
    return craft_meta_payload(bitstring(payload)[end-MINIMUM_CHANNEL_SIZE+1:end], capacity)
end

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
    - Open port on Target (in env (target))
    - TCP Server Mac (or first gw mac)
    - TCP Server IP
    - TCP Server Port

=#

function tcp_ack_bounce_template(target_mac::NTuple{6, UInt8}, target_ip::UInt32, target_listen_port::UInt16,
        server_mac::NTuple{6, UInt8}, server_ip::UInt32, server_port::UInt16)
    return Dict{Symbol, Any}(
        :payload => Vector{UInt8}("Covert packet!"), # Obviously not a real payload
        :network_type => IPv4::Network_Type,
        :transport_type => TCP::Transport_Type,
        :EtherKWargs => Dict{Symbol, Any}(
            :source_mac => target_mac,
            :dest_mac => server_mac,
        ),
        :NetworkKwargs => Dict{Symbol, Any}(
            :source_ip => target_ip,
            :dest_ip => server_ip,
        ),
        :TransportKwargs => Dict{Symbol, Any}(
            :flags => TCP_SYN::UInt8,
            :sport => target_listen_port,
            :dport => server_port,
        )
    )
end
tcp_ack_bounce_template(::NTuple{6, UInt8}, ::UInt32, ::UInt16, ::Nothing, ::Nothing, ::Nothing)::Nothing = nothing
tcp_ack_bounce_template(target_mac::NTuple{6, UInt8}, target_ip::UInt32, target_listen_port::UInt16, q::Union{Channel{Packet}, Vector{Packet}})::Dict{Symbol, Any} = tcp_ack_bounce_template(target_mac, target_ip, target_listen_port, get_tcp_server(q)...)
tcp_ack_bounce_template(target_mac::NTuple{6, UInt8}, target_ip::UInt32, target_listen_port::UInt16)::Dict{Symbol, Any} = tcp_ack_bounce_template(target_mac, target_ip, target_listen_port, get_tcp_server(q)...)
tcp_ack_bounce_template(env::Dict{Symbol, Any}, q::Union{Channel{Packet}, Vector{Packet}}) = tcp_ack_bounce_template(env[:dest_first_hop_mac], env[:dest_ip].host, UInt16(env[:target].covert_options["TCP_ACK_Bounce"]["listen_port"]), get_tcp_server(q)...)
tcp_ack_bounce_template(env::Dict{Symbol, Any}) = tcp_ack_bounce_template(env[:dest_first_hop_mac], env[:dest_ip].host, UInt16(env[:target].covert_options["TCP_ACK_Bounce"]["listen_port"]))

function tcp_ack_bounce_packet(payload::UInt16, template::Dict{Symbol, Any})
    template[:TransportKwargs][:seq] = payload - 1
    return craft_packet(;template...)
end
tcp_ack_bounce_packet(payload::String, template::Dict{Symbol, Any}) = tcp_ack_bounce_packet(parse(UInt16, payload, base=2), template)

function init_tcp_ack_bounce(net_env::Dict{Symbol, Any}, q::Union{Channel{Packet}, Vector{Packet}})::Dict{Symbol, Any}
    return Dict{Symbol, Any}(
        :template => tcp_ack_bounce_template(net_env, q)
    )
end

function decode_tcp_ack_bounce(pkt::Packet)::UInt16
    # ethernet = pkt.payload
    # ip = ethernet.payload
    # tcp = ip.payload
    # return tcp.header.ack
    return pkt.payload.payload.payload.header.ack_num
end


tcp_ack_bounce = covert_method(
    "TCP_ACK_Bounce",
    Layer_type(4), # transport
    "TCP_header",
    5,
    32, # 4 bytes / packet
    (init_tcp_ack_bounce, tcp_ack_bounce_packet),
    decode_tcp_ack_bounce
)

#=
    IPv4_identification utilises the 'random' identification header,
    this can be replaced with encrypted (so essentially random) data.
=#

function ipv4_identification_template(target_mac::NTuple{6, UInt8}, target_ip::UInt32, target_port::UInt16)::Dict{Symbol, Any}
    return Dict{Symbol, Any}(
        :payload => Vector{UInt8}("Covert packet!"), # Obviously not a real payload
        :network_type => nt_IPv4::Network_Type,
        :transport_type => TCP::Transport_Type,
        :EtherKWargs => Dict{Symbol, Any}(
            :dest_mac => target_mac,
        ),
        :NetworkKwargs => Dict{Symbol, Any}(
            :dest_ip => target_ip,
        ),
        :TransportKwargs => Dict{Symbol, Any}(
            :dport => target_port,
        )
    )
end
ipv4_identification_template(env::Dict{Symbol, Any}, ::Union{Channel{Packet}, Vector{Packet}})::Dict{Symbol, Any} = ipv4_identification_template(env[:dest_first_hop_mac], env[:dest_ip].host, UInt16(env[:target].covert_options["IPv4_identification"]["listen_port"]))

function init_ipv4_identification(net_env::Dict{Symbol, Any}, q::Union{Channel{Packet}, Vector{Packet}})::Dict{Symbol, Any}
    return Dict{Symbol, Any}(
        :template => ipv4_identification_template(net_env, q)
    )
end

function ipv4_identification_packet(payload::UInt16; template::Dict{Symbol, Any})
    template[:NetworkKwargs][:identification] = payload
    return craft_packet(;template...)
end
ipv4_identification_packet(payload::String; template::Dict{Symbol, Any}) = ipv4_identification_packet(parse(UInt16, payload, base=2); template=template)

function decode_ipv4_identification(pkt::Packet)::UInt16
    # ethernet = pkt.payload
    # ip = ethernet.payload
    # return ip.header.id
    return pkt.payload.payload.header.id
end

ipv4_identifaction = covert_method(
    "IPv4_identification",
    Layer_type(3), # network
    "IPv4_header",
    8,
    16, # 2 bytes / packet
    (init_ipv4_identification, ipv4_identification_packet),
    decode_ipv4_identification
)

covert_channels = (ipv4_identifaction, tcp_ack_bounce)


function determine_method(covert_methods::Tuple{covert_method})::Tuple{covert_method, Int64}
    #=
        Determine method:

        Parameters:
            - covert_methods : Tuple of covert methods

        Returns:
            - The method that is most likely to be used
            - The intervals at which covert packets should be sent

        Notes:
            Uses a scoring algorithm:
                - v : Number of packets with valid headers for this method
                - c : Covertness of the method, higher is better
                - s : Payload size of the method, higher is better
                - score : (v * c) + s
    =#

    # Get the queue data
    q = get_queue_data(NET_ENV[:queue])

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


    # Sort scores by second value in pair and return highest
    highest = first(sort(scores, by=x->x[2], rev=true))[1]
    return highest[1], target_interval
end

#=

    Covert channel - Micro protocol
    compatability verification

=#

@debug "covert_channel: Covert channels defined" covert_channels

include("microprotocols.jl")

# Verify that channels are large enough for microprotocols
for cc ∈ covert_channels
    if cc.payload_size < MINIMUM_CHANNEL_SIZE
        error("Smallest supported covert channel is $MINIMUM_CHANNEL_SIZE bits")
    end
end

# Verify that there aren't too many channels defined
if length(covert_channels) > (SENTINEL - 1)
    error("Only $(SENTINEL-1) covert channels are supported, increase 'MINIMUM_CHANNEL_SIZE'")
end

# TODO: Check that methods in target::Target are same as ones here, or a subset of.

@debug "covert_channel: Covert channels verified, Done."

