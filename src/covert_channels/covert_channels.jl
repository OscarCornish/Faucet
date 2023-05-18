#=

    Constant definitions

=#

const TCP_ACK           = 0x0010
const TCP_SYN           = 0x0002
const TCP_SYN_ACK       = 0x0012
const TCP_PSH_ACK       = 0x0018

#=

    Covert channels

=#

struct covert_method{Symbol}
    name::String # Readable name
    layer::Layer_type # Layer it exists on
    type::String # What packet type are we aiming for? (Packet will live at .layer)
    covertness::Int8 # 1 - 10
    payload_size::Int64 # bits / packet
    covert_method(name::String, layer::Layer_type, type::String, covertness::Int64, payload_size::Int64)::covert_method{Symbol} = new{Symbol(name)}(name, layer, type, Int8(covertness), payload_size)
end

"""
Checks if a packet has the structure to contain a covert packet of the given type.
"""
function couldContainMethod(packet::Packet, m::covert_method)::Any
    # Verify the packet could be a part of the covert channel
    return split(string(typeof(get_header(packet, m.layer))), ".")[end] == m.type
end

#=
    TCP_ACK_Bounce abuses the TCP handshake,
    by spoofing the source to the destination and sending a request to a server,
    the server responds with an ACK# of the original packets ISN+1,
    the reciver can then ISN-1 and decode using a predefined technique

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
        :payload => Vector{UInt8}(),# ("Covert packet!"), # Obviously not a real payload
        :env => net_env,
        :network_type => IPv4::Network_Type,
        :transport_type => TCP::Transport_Type,
        :EtherKWargs => Dict{Symbol, Any}(
            :dest_mac => dest_mac,
            :source_mac => net_env[:src_mac]#net_env[:dest_first_hop_mac]
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
    template[:TransportKwargs][:seq] = payload - 0x1
    return template
end
encode(m::covert_method{:TCP_ACK_Bounce}, payload::String; template::Dict{Symbol, Any})::Dict{Symbol, Any} = encode(m, parse(UInt32, payload, base=2); template=template)

# Decode function for TCP_ACK_Bounce
decode(::covert_method{:TCP_ACK_Bounce}, pkt::Packet)::UInt32 = pkt.payload.payload.payload.header.ack_num

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
    template[:NetworkKwargs][:identification] = payload
    return template
end
encode(m::covert_method{:IPv4_Identification}, payload::String; template::Dict{Symbol, Any})::Dict{Symbol, Any} = encode(m, parse(UInt16, payload, base=2); template=template)

# Decode function for IPv4_Identification
decode(::covert_method{:IPv4_Identification}, pkt::Packet)::UInt16 = pkt.payload.payload.header.id

"""
Array of all covert methods, the order of these must be the same between sender & target
"""
covert_methods = Vector{covert_method}([
    tcp_ack_bounce,
    ipv4_identifaction,
])


"""
```markdown
Perform calculations for each covert_method based on the environment.

Note:
 - Blacklisted methods are penalised (-90% score)
 - Current method is encouraged (+10% score)
```
"""
function method_calculations(covert_methods::Vector{covert_method}, env::Dict{Symbol, Any}, Eₚ::Vector{Int64}=[], current_method::Int64=0)::NTuple{2, Vector{Float64}}
    # Get the queue data
    q = get_queue_data(env[:queue])

    # Covert score, higher is better : Method i score = scores[i]
    S = zeros(Float64, length(covert_methods))
    # Rate at which to send covert packets : Method i rate = rates[i]
    R = zeros(Float64, length(covert_methods))
    
    if isempty(q)
        @error "No packets in queue, cannot determine method" q
        return S, R
    end
    
    #@warn "Hardcoded response to determine_method"
    L = [get_layer_stats(q, Layer_type(i)) for i ∈ 2:4]

    # Eₗ : Environment length : Number of packets in queue
    Eₗ = length(q)

    # Eᵣ : Environment rate : (Packets / second)
    Eᵣ = Eₗ / abs(last(q).cap_header.timestamp - first(q).cap_header.timestamp)

    # Eₛ : Environment desired secrecy : User supplied (Default: 5)
    Eₛ = env[:desired_secrecy]

    Eₕ = get_local_host_count(q, env[:dest_ip])

    for (i, method) ∈ enumerate(covert_methods)
        Lᵢ_temp = filter(x -> method.type ∈ keys(x), L)
        if isempty(Lᵢ_temp)
            @warn "No packets with valid headers" method.type L
            continue
        end
        # Lᵢ : the layer that method i exists on
        Lᵢ = Lᵢ_temp[1]

        # Lₛ : The sum of packets that have a valid header in Lᵢ
        Lₛ = +(collect(values(Lᵢ))...)

        # Lₚ : Percentage of total traffic that this layer makes up
        Lₚ = Lₛ / Eₗ

        # Pᵢ is the percentage of traffic 
        Pᵢ = Lₚ * (Lᵢ[method.type] / Lₛ)

        # Bᵢ is the bit capacity of method i
        Bᵢ = method.payload_size

        # Cᵢ is the penalty / bonus for the covertness
        #  has bounds [0, 2] -> 0% to 200% (± 100%)
        Cᵢ = 1 - ((method.covertness - Eₛ) / 10)

        # Score for method i
        #  Pᵢ * Bᵢ : Covert bits / Environment bits
        #  then weight by covertness
        #@info "S[i]" Pᵢ Bᵢ Cᵢ Pᵢ * Bᵢ * Cᵢ
        S[i] = Pᵢ * Bᵢ * Cᵢ

        # Rate for method i
        #  Eᵣ * Pᵢ : Usable header packets / second
        #  If we used this much it would be +100% of the environment rate, so we scale it down
        #  by dividing by hosts on the network, Eₕ.
        #  then weight by covertness
        #  We don't want to go over the environment rate, so reshape covertness is between [0, 1] (1 being 100% of env rate)
        #  (Eᵣ * Pᵢ * (Cᵢ / 2)) / Eₕ : Rate of covert packets / second
        #  ∴ 1 / Eᵣ * Pᵢ * (Cᵢ / 2) : Interval between covert packets
        #@info "R[i]" Eₕ Eᵣ Pᵢ Cᵢ/2 Eₕ / (Eᵣ * Pᵢ * (Cᵢ / 2))
        R[i] = Eₕ  / (Eᵣ * Pᵢ * (Cᵢ / 2)) 
    end

    # Eₚ (arg) : Environment penalty : Penalty for failing to work previously
    for i ∈ Eₚ
        S[i] *= 0.1 # 10% of original score
    end

    current_method != 0 && (S[current_method] *= 1.1) # Encourage current method (+10%)

    S[1] *= 4 # Encourage IPv4_Identification so we can block it later

    return S, R
end

"""
Return the index of the method with the highest score, and the interval to send packets at.

The calculations are done in [`method_calculations`](@ref)
"""
function determine_method(covert_methods::Vector{covert_method}, env::Dict{Symbol, Any}, penalities::Vector{Int64}=[], current_method::Int64=0)::Tuple{Int64, Float64}
    # Determine the best method to use
    S, R = method_calculations(covert_methods, env, penalities, current_method)

    # i : index of best method
    # Sᵢ : score of best method
    Sᵢ, i = findmax(S)
    # Rᵢ : rate of best method
    Rᵢ = R[i]

    if allequal([S..., 0.0])
        # If all scores are 0 then we have no valid methods, default to 1, with a large time interval
        return 1, 100.0
    end
    # @debug "Determined covert method" covert_methods[i].name score=Sᵢ rate=Rᵢ

    # Sort scores by second value in pair (score) and return highest
    return i, 1.0
    return i, Rᵢ
end
