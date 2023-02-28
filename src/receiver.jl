ENV["JULIA_DEBUG"] = "all"

include("main.jl")

using ..Inbound: init_receiver, listen
using ..CovertChannels: covert_methods

queue = init_receiver(:local)

data = listen(queue, covert_methods)

open("plaintext", "w") do io
    write(io, data)
end
 