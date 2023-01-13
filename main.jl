#=

    Main

    Setup modules, including the files from inside the module folder

=#

include("constants.jl")

module environment

    export init_queue, get_tcp_server

    include("environment/headers.jl")
    include("environment/query.jl")
    include("environment/queue.jl")

end

