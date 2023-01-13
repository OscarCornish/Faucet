using Serialization
using Sockets
using Random

#=

    Environment.jl

    Functions relating to the network environment:
     - Environment data structure
     - Querying types
     - Picking method

=#

@debug "environment: Loading..."

include("headers.jl")

# Make a FIFO of packets, 
environment_q = Channel{Packet}(ENVIRONMENT_QUEUE_SIZE)

@debug "environment: Defined environment_q" environment_q

# dump_queue & load_queue are for development purposes only, to save me having to capture packets everytime
# TODO: May also expand to have 2 serialised queues, one to favour method A and the other method B...

function dump_queue(q::Channel{Packet}, dump::String="q")
    qdata = Vector{Packet}()
    while length(qdata) <= ENVIRONMENT_QUEUE_SIZE
        x = take!(q)
        push!(qdata, x)
    end
    serialize("captures/$dump.jls", qdata)
end

function load_queue(dump::String)::Vector{Packet}
    return deserialize("captures/$dump.jls")
end

function get_headers(p::Packet)::Vector{Header}
    headers = Vector{Header}()
    layer = p.payload
    while true
        push!(headers, layer.header)
        layer = layer.payload
        if !isa(layer, Layer)
            return headers
        end
    end
end

function get_header(p::Packet, l::Layer_type)::Union{Header, Missing}
    headers = get_headers(p)
    for i=1:lastindex(headers)
        if Layer_type(i+1) == l
            return headers[i]
        end
    end
    return missing
end

get_layer_stats(q::Channel{Packet}, l::Layer_type)::Dict{String, Int64} = get_layer_stats(get_queue_data(q), l)

function get_layer_stats(v::Vector{Packet}, l::Layer_type)::Dict{String, Int64}
    packet_headers = [get_header(p, l) for p ∈ v]
    info = Dict{String, Int64}()
    info["Missing"] = 0
    for h ∈ packet_headers
        if ismissing(h)
            info["Missing"] += 1
        else
            prot = string(typeof(h))
            if prot ∈ keys(info)
                info[prot] += 1
            else
                info[prot] = 1
            end
        end
    end
    if info["Missing"] == 0
        delete!(info, "Missing")
    end
    return info
end

function get_queue_data(q::Channel{Packet})::Vector{Packet}
    return q.data
end

# Using HEADER_Ethernet as base of the tree, we can associate a layer type string with an index in headers
function get_layer2index(tree_root::Node)::Dict{String, Int64}
    layer2index = Dict{String, Int64}()
    current_layer_nodes = Vector{Node}([tree_root])
    next_layer_nodes = Vector{Node}()
    current_layer = 1
    while length(current_layer_nodes) > 0
        for node ∈ current_layer_nodes
            layer2index[string(node.type)] = current_layer
            for child ∈ node.children
                push!(next_layer_nodes, child)
            end
        end
        current_layer_nodes = next_layer_nodes
        next_layer_nodes = Vector{Node}()
        current_layer += 1
    end
    return layer2index
end

layer2index = get_layer2index(HEADER_Ethernet)

function query_header(header::Header, arguments::Dict{Symbol, Any})::Bool
    # Returns true if the header matches the arguments
    if isempty(arguments)
        return true
    end
    o = Vector{Bool}()
    for (k, v) ∈ arguments
        data = getfield(header, k)
        if typeof(v) == Vector{typeof(data)}
            push!(o, data ∈ v)
        else
            push!(o, data == v)
        end
    end
    return all(o)
end
query_header(::Header, ::Nothing)::Bool = true
query_header(::Nothing, ::Dict{Symbol, Any})::Bool = false

function query_headers(headers::Vector{Header}, arguments::Dict{String, Dict{Symbol, Any}})::Bool
    # Returns true if the headers match the arguments
    o = Vector{Bool}()
    for (k, v) ∈ arguments
        push!(o, query_header(get(headers, layer2index[k], nothing), v))
    end
    return all(o)
end

function query_queue(q::Vector{Packet}, arguments::Vector{Dict{String, Dict{Symbol, Any}}})::Vector{Vector{Header}}
    #=
        Query queue:

        Parameters:
            - arguments : Vector of Dictionary of dictionaries
                Each dictionary in the vector refers to a match case,
                each match case is a dictionary of layer types and required values
        
        Returns:
            - Vector of packet headers that match the query

        Example:
        arguments = [
            {
                TCP_header => {
                    :sport => 0x2f11 # 12049
                    :dport => 0x0050 # 80
                }
            },
            {
                IPv4_header => {
                    :ihl => [0x05, 0x06]
                }
            }
        ]
        will return all headers for packets that either have:
            (tcp header with a source port of 12049 AND destination port of 80) OR
            (ipv4 header with an ihl of 5 or 6)
    =#
    query = Vector{Vector{Header}}()
    for p ∈ q
        headers = get_headers(p)
        if any([query_headers(headers, case) for case ∈ arguments])
            push!(query, headers)
        end
    end
    return query
end
query_queue(q::Channel{Packet}, args::Vector{Dict{String, Dict{Symbol, Any}}})::Vector{Vector{Header}} = query_queue(get_queue_data(q), args)

# Common tcp services (80, 443, etc.)
const TCP_SERVICES = [UInt16(80), UInt16(443), UInt16(20), UInt16(21), UInt16(22), UInt16(25), UInt16(143)]

function _get_tcp_server(q::Vector{Packet})::Union{Tuple{NTuple{6, UInt8}, UInt32, UInt16}, Tuple{Nothing, Nothing, Nothing}}
    common_query = Vector{Dict{String, Dict{Symbol, Any}}}([
        Dict{String, Dict{Symbol, Any}}(
            "TCP_header" => Dict{Symbol, Any}(
                :dport => TCP_SERVICES
            )
        )
    ])
    # Clients connected to common TCP Services
    services = query_queue(q, common_query)
    
    syn_query = Vector{Dict{String, Dict{Symbol, Any}}}([
        Dict{String, Dict{Symbol, Any}}(
            "TCP_header" => Dict{Symbol, Any}(
                :syn => true
            )
        )
    ])

    mac, ip, port = nothing, nothing, nothing
    if !isempty(services)
        service = pop!(services) # Most recently active one
        # This is a packet going toward tcp service
        # Ethernet_header -> tcp server mac (of next hop from local perspective)
        # IP_header.daddr -> tcp server ip
        # TCP_header.dport -> tcp server port
        mac = getfield(service[layer2index["Ethernet_header"]], :source)
        ip = getfield(service[layer2index["IPv4_header"]], :daddr)
        port = getfield(service[layer2index["TCP_header"]], :dport)
    else
        syn_services = query_queue(q, syn_query)
        if !isempty(syn_services)
            service = pop!(syn_services) # Most recently active one
            # Again, a packet going toward a tcp server
            mac = getfield(service[layer2index["Ethernet_header"]], :source)
            ip = getfield(service[layer2index["IPv4_header"]], :daddr)
            port = getfield(service[layer2index["TCP_header"]], :dport)
        end
    end
    return (mac, ip, port)
end

function get_tcp_server(q::Vector{Packet})::Union{Tuple{NTuple{6, UInt8}, UInt32, UInt16}, Tuple{Nothing, Nothing, Nothing}}
    if !haskey(NET_ENV, :tcp_server)
        NET_ENV[:tcp_server] = _get_tcp_server(q)
    end
    return NET_ENV[:tcp_server]
end
get_tcp_server(q::Channel{Packet})::Union{Tuple{NTuple{6, UInt8}, UInt32, UInt16}, Tuple{Nothing, Nothing, Nothing}} = get_tcp_server(get_queue_data(q))

@debug "environment: Defined queue functions"
@debug "environemnt: Done."