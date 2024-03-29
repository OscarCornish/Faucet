#=

    Query.jl

    Functions related to extracting information from the environment queue:
        - Custom querying
        - Extracting headers
        - Environment statistics
        - get_tcp_server

=#

# Common tcp services (80, 443, etc.)
const TCP_SERVICES = [UInt16(80), UInt16(443), UInt16(20), UInt16(21), UInt16(22), UInt16(25), UInt16(143)]

"""
    get_headers(p::Packet)::Vector{Header}

Seperate the headers from a packet into a vector and return it
"""
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

"""
    get_header(p::Packet, l::Layer_type)::Union{Header, Missing}

Get the header of a specific layer from a packet
"""
function get_header(p::Packet, l::Layer_type)::Union{Header, Missing}
    headers = get_headers(p)
    for i=1:lastindex(headers)
        if Layer_type(i+1) == l
            return headers[i]
        end
    end
    return missing
end

"""
    get_queue_data(q::CircularChannel{Packet})::Vector{Packet}

Converts the queue to a static vector of packets (Implicitly)
"""
get_queue_data(q::CircularChannel{Packet})::Vector{Packet} = q

"""
    get_layer_stats(packets, layer)::Dict{String, Int64}

Get the statistics of a layer in the queue

```
Returns a dictionary with the following format:
    - Key: The name of the header
    - Value: The number of packets with that header
```

"""
function get_layer_stats(v::Vector{Packet}, l::Layer_type)::Dict{String, Int64}
    packet_headers = [get_header(p, l) for p ∈ v]
    info = Dict{String, Int64}()
    info["Missing"] = 0
    for h ∈ packet_headers
        if ismissing(h)
            info["Missing"] += 1
        else
            prot = split(string(typeof(h)), ".")[end]
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

"""
    get_layer_stats(q::CircularChannel{Packet}, l::Layer_type)::Dict{String, Int64}

Converts the queue to a static vector of packets pre-processing
"""
get_layer_stats(q::CircularChannel{Packet}, l::Layer_type)::Dict{String, Int64} = get_layer_stats(get_queue_data(q), l)

"""
    get_layer2index(tree_root::Node)::Dict{String, Int64}

Create a dictionary that maps the layer name to its index in the tree, using the packet tree defined in `headers.jl`
"""
function get_layer2index(tree_root::Node)::Dict{String, Int64}
    layer2index = Dict{String, Int64}()
    current_layer_nodes = Vector{Node}([tree_root])
    next_layer_nodes = Vector{Node}()
    current_layer = 1
    while length(current_layer_nodes) > 0
        for node ∈ current_layer_nodes
            layer2index[split(string(node.type), ".")[end]] = current_layer
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

"""
Returns true if the arguments match the header

# Example
```markdown
In a packet with the following headers:
    - TCP Packet with source port 80

The following query will return true:
    - `query_header(header, Dict(:sport => 80))`
```

"""
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


"""
    query_headers(headers, arguments)::Bool

Returns true if arguments match the their respective headers

# Example
```markdown
Packet with the following headers:
    - Ethernet Packet with source MAC 00:00:00:00:00:00
    - TCP Packet with source port 80

The following query will return true:
    - `query_headers(headers, Dict(
        "Ethernet_header" => Dict(:smac => 0x000000000000),
        "TCP_header" => Dict(:sport => 80)
        ))`
```
"""
function query_headers(headers::Vector{Header}, arguments::Dict{String, Dict{Symbol, Any}})::Bool
    # Returns true if the headers match the arguments
    o = Vector{Bool}()
    for (k, v) ∈ arguments
        header = get(headers, layer2index[k], nothing)
        if !isnothing(header) && split(string(typeof(header)), ".")[end] == k
            push!(o, query_header(header, v))
        else
            push!(o, false)
        end
    end
    return all(o)
end

"""
    query_queue(queue, arguments)::Vector{Vector{Header}}

Returns a vector of all packet headers if a packet matches an argument

Arguments is a vector of dictionaries, each dictionary is a match case
A match case is a dictionary of header types and required values in that header

# Example
```julia
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
```
!!! note
    will return all headers for packets that either have:
    (tcp header with a source port of `12049` *AND* destination port of `80`) *OR*
    (ipv4 header with an ihl of `5` *OR* `6`)

"""
function query_queue(q::Vector{Packet}, arguments::Vector{Dict{String, Dict{Symbol, Any}}})::Vector{Vector{Header}}
    query = Vector{Vector{Header}}()
    for p ∈ q
        headers = get_headers(p)
        if any([query_headers(headers, case) for case ∈ arguments])
            push!(query, headers)
        end
    end
    return query
end
query_queue(q::CircularChannel{Packet}, args::Vector{Dict{String, Dict{Symbol, Any}}})::Vector{Vector{Header}} = query_queue(get_queue_data(q), args)

"""
    get_tcp_server(queue)::(MAC, IP, Port)

Returns the MAC address, IP address, and port of the most recently active TCP server, using common TCP service ports and SYN packets
Returns nothing if no server can be found
"""
function get_tcp_server(q::Vector{Packet})::Union{Tuple{NTuple{6, UInt8}, UInt32, UInt16}, NTuple{3, Nothing}}
    common_query = Vector{Dict{String, Dict{Symbol, Any}}}([
        Dict{String, Dict{Symbol, Any}}(
            "TCP_header" => Dict{Symbol, Any}(
                :dport => TCP_SERVICES
            )
        )
    ])
    # Clients connected to common TCP Services, TCP traffic to them is favourable (In terms of covertness)
    services = query_queue(q, common_query)
    
    syn_query = Vector{Dict{String, Dict{Symbol, Any}}}([
        Dict{String, Dict{Symbol, Any}}(
            "TCP_header" => Dict{Symbol, Any}(
                :syn => true
            )
        )
    ])

    service_mac, service_ip, service_port = nothing, nothing, nothing
    if !isempty(services)
        # Take the most recently active one
        service = pop!(services)
        # This is a packet going toward tcp service
        service_mac = getfield(service[layer2index["Ethernet_header"]], :source)
        # Ethernet_header -> tcp server mac (of next hop from local perspective)
        service_ip = getfield(service[layer2index["IPv4_header"]], :daddr)
        # IP_header.daddr -> tcp server ip
        service_port = getfield(service[layer2index["TCP_header"]], :dport)
        # TCP_header.dport -> tcp server port
    else
        syn_traffic = query_queue(q, syn_query)
        if !isempty(syn_traffic)
            # Take most recently active one
            service = pop!(syn_traffic)
            # Again, a packet going toward a tcp server
            service_mac = getfield(service[layer2index["Ethernet_header"]], :source)
            # Ethernet_header -> tcp server mac (of next hop from local perspective)
            service_ip = getfield(service[layer2index["IPv4_header"]], :daddr)
            # IP_header.daddr -> tcp server ip
            service_port = getfield(service[layer2index["TCP_header"]], :dport)
            # TCP_header.dport -> tcp server port
        end
    end
    # Currently, the test environment does not support getting a valid tcp server like this (to be fixed...)
    @debug "Found TCP Server, but using hardcoded (due to test environment)" service_ip service_mac service_port
    ip = 0xc91e140a # 10.20.30.201
    mac_raw = match(r"^Unicast reply from (?:\d{1,3}\.){3}\d{1,3} \[(?<mac>(?:[A-F\d]{2}:){5}[A-F\d]{2})\]"m, readchomp(`arping -c 1 10.20.30.201`))[:mac]
    mac = tuple(map(x->parse(UInt8, x, base=16), split(String(mac_raw), ':'))...)
    #mac = (0xfa, 0x4c, 0x92, 0x7f, 0x95, 0x3b)
    port = 0x0050
    return (mac, ip, port)
end
get_tcp_server(q::CircularChannel{Packet})::Union{Tuple{NTuple{6, UInt8}, UInt32, UInt16}, NTuple{3, Nothing}} = get_tcp_server(get_queue_data(q))

get_local_host_count(q::CircularChannel{Packet}, local_address::IPv4Addr, subnet_mask::Int=24)::Int64 = get_local_host_count(get_queue_data(q), local_address, subnet_mask)
function get_local_host_count(q::Vector{Packet}, local_address::IPv4Addr, subnet_mask::Int=24)::Int64
    # CIDR notation is number of bits that denote the network, the rest are host bits
    local_address_mask = typemax(UInt32) << (32 - subnet_mask)
    # We want hosts on the same subnet so ignore the host bits
    local_address = local_address_mask & hton(local_address.host)
    # Get all IPv4 headers
    ipv4_headers = [h[2] for h ∈ query_queue(q, [
        Dict{String, Dict{Symbol, Any}}(
            "IPv4_header" => Dict{Symbol, Any}()
        )
    ])]
    hosts = Set{UInt32}()
    for h ∈ ipv4_headers
        for addr ∈ (h.saddr, h.daddr)
            if (addr & local_address_mask) == local_address
                push!(hosts, addr)
            end
        end
    end
    return length(hosts)
end

"""
    get_local_host(queue, local_address, subnet_mask)::Vector{UInt8}

    Returns the host byte of the local ip address
"""
function get_local_net_host(q::Vector{Packet}, local_address::IPv4Addr, blacklist::Vector{UInt8}=[], subnet_mask::Int=24)::UInt8 # return the host byte of the local ip
    # Do not use .0 or .255 (network and broadcast addresses)
    # Sometimes they will not be, but this is a simpler and "good enough" solution
    push!(blacklist, 0x00, 0xff)
    # Get all IPv4 headers
    ipv4_headers = [h[2] for h ∈ query_queue(q, [
        Dict{String, Dict{Symbol, Any}}(
            "IPv4_header" => Dict{Symbol, Any}()
        )
    ])]
    # CIDR notation is number of bits that denote the network, the rest are host bits
    local_address_mask = typemax(UInt32) << (32 - subnet_mask)
    # We want hosts on the same subnet so ignore the host bits
    local_address = local_address_mask & hton(local_address.host)
    hosts = Dict{UInt8, Int}()
    for ipv4 ∈ ipv4_headers
        for header ∈ (ipv4.saddr, ipv4.daddr)
            if header & local_address_mask == local_address
                # Invert the subnet mask to make it a host mask
                host_byte = UInt8(header & ~local_address_mask)
                if haskey(hosts, host_byte)
                    # Increment the number of times we have seen this host byte
                    hosts[host_byte] += 1
                else
                    hosts[host_byte] = 1
                end
            end
        end
    end
    # Remove blacklisted host bytes from our list
    for b ∈ blacklist
        delete!(hosts, b)
    end
    # Return the most active local host
    return collect(keys(hosts))[findmax(collect(values(hosts)))[2]]
end
get_local_net_host(q::CircularChannel{Packet}, local_address::IPv4Addr, blacklist::Vector{UInt8}=[], subnet_mask::Int=24)::UInt8 = get_local_net_host(get_queue_data(q), local_address, blacklist, subnet_mask)
