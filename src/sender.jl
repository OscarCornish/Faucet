
include("main.jl")

using ..CovertChannels: covert_methods
using .Environment: init_queue
using .Outbound: init_environment, send_covert_payload

@debug "Creating queue"
net_env = init_environment(target, init_queue())

covert_payload = Vector{UInt8}("Recoverable hello world!")

@debug "Sending covert payload" payload=covert_payload

send_covert_payload(covert_payload, covert_methods, net_env)

@info "Finished sending covert payload"

exit(0)
