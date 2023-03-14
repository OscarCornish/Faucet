#ENV["JULIA_DEBUG"] = "main"

include("main.jl")

using ..Inbound: init_receiver, listen
using ..CovertChannels: covert_methods

queue = init_receiver(:local)

#@debug "Listening..."

data = listen(queue, covert_methods)

open("plaintext", "w") do io
    write(io, data)
end
 