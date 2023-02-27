ENV["JULIA_DEBUG"] = "all"

include("main.jl")

using ..Inbound: init_reciever, listen
using ..CovertChannels: covert_methods

queue = init_reciever(:local)

data = listen(queue, covert_methods)

open("plaintext", "w") do io
    write(io, data)
end
 