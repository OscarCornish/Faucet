ENV["JULIA_DEBUG"] = "all"

include("main.jl")

using .Environment: init_queue
using .CovertChannels: covert_methods
using .Outbound: init_environment, send_covert_payload

net_env = init_environment(target, init_queue())

covert_payload = Vector{UInt8}("Hello covert world!")

send_covert_payload(covert_payload, covert_methods, net_env)
