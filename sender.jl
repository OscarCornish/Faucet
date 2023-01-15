#=

    server.jl

    FAUCET
    F - Framework of
    A - Adaptive
    U - Undetected
    C - Communication
    E - Environment
    T - Tools

=#

ENV["JULIA_DEBUG"] = "Main"
@debug "server: Loading..."

# Load the target (reciver object)
include("target.jl")

include("network.jl")
# -> environment.jl
#   -> headers.jl
#       -> constants.jl
include("covert_channel.jl")
# -> constants.jl
# -> microprotocols.jl
#   -> constants.jl
include("sender.jl")

NET_ENV = init_environment(target, environment_q)

@debug "server: Environment initialised fully" NET_ENV

covert_payload = Vector{UInt8}("Hello covert world!")

send_covert_payload(covert_payload, covert_channels, NET_ENV)

#=
#=

    Sending a packet example

=#

payload = Vector{UInt8}("Hello world!")
network_t = IPv4::Network_Type
transport_t = TCP::Transport_Type
ipkwargs = Dict{Symbol, Any}()
tcpkwargs = Dict{Symbol, Any}()

pkt = craft_packet(payload, network_t, transport_t, ipkwargs, tcpkwargs)
@debug "server: Crafted packet" pkt

open("dummy", "w") do io
    write(io, pkt)
end

@debug "server: Packet written to file, Done."
=#