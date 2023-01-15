# Do this in a better way, this is clunky
function mac_from_ip(ip::String)::NTuple{6, UInt8}
    for match ∈ eachmatch(ip_a_regex, readchomp(`ip a`))
        if match[:addr] == ip
            return mac(match[:mac])
        end
    end
    @error "Could not find mac address for ip $ip" matches=collect(eachmatch(ip_a_regex, readchomp(`ip a`)))
    error("Could not find mac address for ip $ip")
end
mac_from_ip(ip::IPAddr) = mac_from_ip(string(ip))

# Do this in a better way, this is clunky
function subnet_mask(ip::String)::UInt32
    for match ∈ eachmatch(ip_a_regex, readchomp(`ip a`))
        if match[:addr] == ip
            return subnet_mask(parse(Int64, match[:cidr]))
        end
    end
    return nothing
end
subnet_mask(ip::IPAddr) = subnet_mask(string(ip))

function get_ip_addr(dest_ip::String)::Tuple{String, Union{IPAddr, Nothing}, IPAddr} # Interface, Gateway, Source
    for match ∈ eachmatch(ip_r_regex, readchomp(`ip r get $dest_ip`))
        if match[:dest_ip] == dest_ip
            iface = string(match[:if])
            gw = isnothing(match[:gw]) ? nothing : IPv4Addr(match[:gw])
            src = IPv4Addr(match[:src_ip])
            return iface, gw, src
        end
    end
end
get_ip_addr(dest_ip::IPAddr)::Tuple{String, Union{IPAddr, Nothing}, IPAddr} = get_ip_addr(string(dest_ip))

function first_hop_mac(target::String, iface::String)::NTuple{6, UInt8}
    for match ∈ eachmatch(ip_neigh_regex, readchomp(`ip neigh`))
        if match[:ip] == target
            return mac(match[:mac])
        end
    end
    # Force new arp entry
    # TODO: Test if `ip neigh get $addr dev $iface` will perform a new request
    #       in the event the external host is not in the ip neigh table
    #x = readchomp(`ip `)
    return nothing
end
first_hop_mac(target::IPAddr, iface::String)::NTuple{6, UInt8} = first_hop_mac(string(target), iface)

"""
    get_socket()
Return a raw socket, wrapped into an `IOStream`
"""
function get_socket()::IOStream
    fd = ccall(:socket, Cint, (Cint, Cint, Cint), AF_PACKET, SOCK_RAW, hton(ETH_P_ALL))
    return fdio(fd)
end

# TODO: Currently we get the iface from the target ip, but the queue is created
#           with a specific iface, so we should use that.

function init_environment(target::Target, q::Channel{Packet})::Dict{Symbol, Any}
    env = Dict{Symbol, Any}()
    # Get dest ip as UInt32
    env[:dest_ip] = target.ip
    # Get src ip from sending interface
    iface, gw, src_ip = get_ip_addr(target.ip)
    # Get sending interface + address
    env[:interface] = iface
    env[:src_ip] = src_ip
    # Get mac address from sending interface
    env[:src_mac] = mac_from_ip(env[:src_ip])
    # Get subnet mask from sending interface
    env[:subnet_mask] = subnet_mask(env[:src_ip])
    # Get first hop mac address
    env[:dest_first_hop_mac] = isnothing(gw) ? first_hop_mac(env[:dest_ip], iface) : first_hop_mac(gw, iface)
    # Target object
    env[:target] = target
    # Queue
    env[:queue] = q
    # Get socket
    env[:sock] = open("dummy-socket", "w") # get_socket()
    @info "Using dummy socket"
    return env
end