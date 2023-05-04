#ENV["JULIA_DEBUG"] = "all"

include("main.jl")

using .Environment: init_queue
using .CovertChannels: covert_methods
using .Outbound: init_environment, send_covert_payload

@debug "Creating queue"
queue = init_queue()
net_env = init_environment(target, queue)

covert_payload = Vector{UInt8}("Recoverable hello world!")

@debug "Sending covert payload" payload=covert_payload

send_covert_payload(covert_payload, covert_methods, net_env)

@info "Finished sending covert payload"
