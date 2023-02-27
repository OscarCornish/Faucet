using AES
using Dates

function dec(data::Vector{String})::Vector{UInt8}
    # Convert to bytes
    bytes = Vector{UInt8}()
    if length(data) % 8 != 0
        @error "Data is not a multiple of 8, either recieved additional packets, or missing some"
        error("Data length not a multiple of 8")
    end
    for i ∈ 1:8:length(data)
        push!(bytes, parse(UInt8, data[i:i+7], base=2))
    end
    # Recreate cipher text
    ct = CipherText(
        bytes,
        target.AES_IV,
        length(target.AES_PSK) * 8,
        AES.CBC
    )
    cipher = AESCipher(;key_length=128, mode=AES.CBC, key=target.AES_PSK)

    # decrypt
    return decrypt(ct, cipher)
end
    
# Get queue with filter

function init_reciever(bfp_filter::Union{String, Symbol})::Channel{Packet}
    if bfp_filter == :local
        bfp_filter = local_bound_traffic()
    end
    if bfp_filter == :all
        bfp_filter = ""
    end
    if typeof(bfp_filter) != String
        throw(ArgumentError("bfp_filter must be a string, :local, or :all"))
    end
    queue = init_queue(bfp_filter)
    return queue
end

# Listen for sentinel on first method

function process_data(data::Unsigned)::String
    # Convert to bitstring, and strip the microprotocol bits
    return bitstring(data)[2:end]
end

function process_meta(data::Unsigned)::Tuple{Symbol, Any}
    meta = bitstring(data)[1:MINIMUM_CHANNEL_SIZE]
    if meta == SENTINEL
        return (:sentinel, nothing)
    else # Return 
        return (:meta, parse(Int64, meta[2:end], base=2))
    end
end
    
function process_packet(current_method::covert_method, packet::Packet)::Tuple{Symbol, Any}
    # decode packet
    data = decode(current_method, packet)
    # check if sentinel
    if data & MP_MASK == MP_DATA
        return (:data, process_data(data))
    else # data & MP_MASK == MP_META
        return process_meta(data)
    end
end

# Once sentinel starts, initiate proper listening

function listen(queue::Channel{Packet}, methods::Vector{covert_method})::Vector{UInt8}
    # Listen for sentinel
    data = Vector{String}()
    sentinel_recieved = false
    current_method = methods[1]
    @debug "Listening for sentinel" current_method
    while true
        type, kwargs = process_packet(current_method, take!(queue))
        if type == :sentinel
            if sentinel_recieved # If we have already recieved a sentinel, we have finished the data
                break
            else
                @info "Sentined recieved, beginning data collection"
                sentinel_recieved = true
            end
            sentinel_recieved = true
        elseif sentinel_recieved && type == :meta
            @info "Switching to method" method=methods[kwargs]
            current_method = methods[kwargs]
        elseif sentinel_recieved && type == :data
            @info "Recieved data" data=kwargs
            push!(data, kwargs)
        end
    end
    @info "Data collection complete, decrypting..."
    return dec(data)
end

# return to listening for sentinel

function listen_forever(queue::Channel{Packet}, methods::Vector{covert_method})
    while true
        data = listen(queue, methods)
        file = "comms/$(now().instant.periods.value).bytes"
        @info "Communication stream finished, writing to file" file=file
        open(file, "w") do io
            write(io, data)
        end
    end
end


#### issues

# How to handle multiple sentinels?  Do we need to?  Can we just limit to one sender one reciever
# What happens if the sender breaks off?  Do we need to handle this?  Can we just assume that the sender will not break off?


# Also fix other queue, probably mismatch in the queue being used somewhere...
# otherwise just fake it for now, getting the algo to alternate would be nice
# + plus can define send times, so it will probably be faster.