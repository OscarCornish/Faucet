"""
Get the mac address of the interface with the given ip

This is a unstable wrapper around `ip a` and `ip neigh`
"""
function mac_from_ip(ip::String, type::Symbol=:local)::NTuple{6, UInt8}
    if type == :local
        for match ∈ eachmatch(ip_address_regex, readchomp(`ip a`))
            if match[:ip] == ip
                return mac(match[:mac])
            end
        end
    elseif type == :remote
        cmd_output = readchomp(`ip neigh`)
        for match ∈ eachmatch(ip_neigh_regex, cmd_output)
            if match[:ip] == ip
                return mac(match[:mac])
            end
        end
    else
        error("Invalid type: $type")
    end
    error("Unable to find MAC address for IP: $ip")
end
mac_from_ip(ip::IPAddr, type::Symbol=:local)::NTuple{6, UInt8} = mac_from_ip(string(ip), type)

"""
Return the interface, gateway, and source ip for the given destination ip
"""
function get_ip_addr(dest_ip::String)::Tuple{String, Union{IPAddr, Nothing}, IPAddr} # Interface, Gateway, Source
    for match ∈ eachmatch(ip_route_regex, readchomp(`ip r get $dest_ip`))
        if match[:dest_ip] == dest_ip
            iface = string(match[:iface])
            gw = isnothing(match[:gw]) ? nothing : IPv4Addr(match[:gw])
            src = IPv4Addr(match[:src_ip])
            return iface, gw, src
        end
    end
end
get_ip_addr(dest_ip::IPAddr)::Tuple{String, Union{IPAddr, Nothing}, IPAddr} = get_ip_addr(string(dest_ip))

const arping_regex = r"^Unicast reply from (?:\d{1,3}\.){3}\d{1,3} \[(?<mac>(?:[A-F\d]{2}:){5}[A-F\d]{2})\]"m

"""
Get the first hop mac address for the given target ip
"""
function first_hop_mac(target::String, iface::String)::NTuple{6, UInt8}
    try
        return mac_from_ip(target, :remote)
    catch e
        x = match(arping_regex, readchomp(`arping -c 1 $target`))
        if !isnothing(x)
            return mac(x[:mac])
        end
        @warn "Unable to find MAC address of $target using arping"
    end
    return nothing
end
first_hop_mac(target::IPAddr, iface::String)::NTuple{6, UInt8} = first_hop_mac(string(target), iface)

"""
Get the interface for the given ip
"""
function get_dev_from_ip(ip::String)::String
    for match ∈ eachmatch(ip_address_regex, readchomp(`ip a`))
        if match[:ip] == ip
            return string(match[:iface])
        end
    end
    error("Unable to find device for IP: $ip")
end
get_dev_from_ip(ip::IPAddr)::String = get_dev_from_ip(string(ip))

"""
Initialise an environment "context" for the given target
"""
function init_environment(target::Target, q::Channel{Packet}, covertness::Int=5)::Dict{Symbol, Any}
    @assert isa(target.ip, IPv4Addr)
    @assert 1 ≤ covertness ≤ 10

    env = Dict{Symbol, Any}()
    # What is the "covertness" we are aiming to achieve?
    env[:desired_secrecy] = covertness
    # Get dest ip as UInt32
    env[:dest_ip] = target.ip
    # Get src ip from sending interface
    iface, gw, src_ip = get_ip_addr(target.ip)
    # Get sending interface + address
    env[:interface] = length(ARGS) ≥ 2 ? ARGS[2] : iface # Override interface if specified in args
    env[:src_ip] = src_ip
    # Get mac address from sending interface
    env[:src_mac] = mac_from_ip(env[:src_ip])
    # Get first hop mac address
    env[:dest_first_hop_mac] = isnothing(gw) ? first_hop_mac(env[:dest_ip], iface) : first_hop_mac(gw, iface)
    # Target object
    env[:target] = target
    # Queue
    env[:queue] = q
    # Get socket
    env[:sock] = get_socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)
    return env
end
