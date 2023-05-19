
include("main.jl")

using ..CovertChannels: covert_methods
using .Environment: init_queue
using .Outbound: init_environment, send_covert_payload

@debug "Creating queue"
net_env = init_environment(target, init_queue())

using Random
alphabet = collect('A':'Z')
rng = MersenneTwister(1234)
covert_payload = UInt8.([alphabet[rand(rng, 1:26)] for i = 1:parse(Int64, ARGS[3])])

@debug "Sending covert payload" payload=covert_payload

send_covert_payload(covert_payload, covert_methods, net_env)

@info "Finished sending covert payload"

sleep(10)
exit(0)
