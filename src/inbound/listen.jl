using AES
using Dates

function dec(data::String)::Vector{UInt8}
    # Remove padding by finding the length we added earlier
    for i = length(data):-1:1
        if i % 8 == 0
            bitlen = lstrip(bitstring(Int64(i/8)), '0')
            if length(data) - i >= length(bitlen)
                if data[i+1:i+length(bitlen)] == bitlen
                    data = data[1:i]
                    break
                end
            end
        end
    end

    # Convert to bytes
    bytes = Vector{UInt8}()
    if length(data) % 8 != 0
        @error "Data is not a multiple of 8, either recieved additional packets, or missing some"
        error("Data length not a multiple of 8")
    end
    bytes = [parse(UInt8, data[i:i+7], base=2) for i ∈ 1:8:length(data)]

    # Recreate cipher text & cipher
    ct = AES.CipherText(
        bytes,
        target.AES_IV,
        length(target.AES_PSK) * 8,
        AES.CBC
    )
    cipher = AES.AESCipher(;key_length=128, mode=AES.CBC, key=target.AES_PSK)
    
    # decrypt
    return decrypt(ct, cipher).parent
end
    
# Get queue with filter

function init_receiver(bfp_filter::Union{String, Symbol})::Channel{Packet}
    if bfp_filter == :local
        bfp_filter = local_bound_traffic()
    end
    if bfp_filter == :all
        bfp_filter = ""
    end
    @debug "Initializing receiver" filter=bfp_filter
    if typeof(bfp_filter) != String
        throw(ArgumentError("bfp_filter must be a string, :local, or :all"))
    end
    return init_queue(bfp_filter)
end

function process_meta(data::String)::Tuple{Symbol, Any}
    meta = data[1:MINIMUM_CHANNEL_SIZE]
    @debug "Processing meta" meta=meta
    if meta == bitstring(SENTINEL)[end-MINIMUM_CHANNEL_SIZE+1:end]
        return (:sentinel, nothing)
    elseif meta == bitstring(DISCARD_CHUNK)[end-MINIMUM_CHANNEL_SIZE+1:end]
        return (:integrity_fail, nothing)
    else # Return 
        return (:method_change, extract_method(data))
    end
end
    
function process_packet(current_method::covert_method, packet::Packet)::Tuple{Symbol, Any}
    if couldContainMethod(packet, current_method)
        data = bitstring(decode(current_method, packet))
        # check if data or meta
        if data[1] == '0'
            return (:data, data[2:end])
        else
            return process_meta(data)
        end
    end
    return (:pass, nothing)
end

# Once sentinel starts, initiate proper listening

function listen(queue::Channel{Packet}, methods::Vector{covert_method})::Vector{UInt8}
    # Listen for sentinel
    local_ip = get_local_ip()
    previous = ""
    data = ""
    chunk = ""
    sentinel_recieved = false
    current_method = methods[1]
    @debug "Listening for sentinel" current_method.name
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

        elseif sentinel_recieved && type == :method_change
            (new_method_index, integrity_key) = kwargs
            @info "Preparing for method change" new_method_index
            # Beacon out  integrity of chunk
            ARP_Beacon(integrity_check(chunk, integrity_key), IPv4Addr(local_ip))
            current_method = methods[new_method_index]
            previous = data
            data *= chunk
            chunk = ""

        elseif sentinel_recieved && type == :integrity_fail
            @warn "Integrity check failed of last chunk, reverting..."
            chunk = ""
            data = previous # Revert 'commit' of chunk
        
        elseif sentinel_recieved && type == :data
            @debug "Data received, adding to chunk" chunk_length=length(chunk) total_length=length(data) data=kwargs
            chunk *= kwargs

        end
    end
    data *= chunk
    @info "Data collection complete, decrypting..."
    return dec(data)
end

# return to listening for sentinel

function listen_forever(queue::Channel{Packet}, methods::Vector{covert_method})
    while true
        data = listen(queue, methods)
        file = "comms/$(now().instant.periods.value).bytes"
        #@info "Communication stream finished, writing to file" file=file
        open(file, "w") do io
            write(io, data)
        end
    end
end

#### issues

# How to handle multiple sentinels?  Do we need to?  Can we just limit to one sender one receiver
# What happens if the sender breaks off?  Do we need to handle this?  Can we just assume that the sender will not break off?


# Also fix other queue, probably mismatch in the queue being used somewhere...
# otherwise just fake it for now, getting the algo to alternate would be nice
# + plus can define send times, so it will probably be faster.