using AES
using Dates

function dec(_data::String)::Vector{UInt8}
    data = remove_padding(_data)

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
    
    decrypted = decrypt(ct, cipher).parent

    padding = decrypted[end]
    if decrypted[end-padding+1:end] == [padding for i in 1:padding]
        return decrypted[1:end-padding]
    else
        return decrypted
    end
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

function try_recover(packet::Packet, integrities::Vector{Tuple{Int, UInt8}}, methods::Vector{covert_method})::Int
    for (i, method) ∈ enumerate(methods)
        if couldContainMethod(packet, method)
            @debug "Checking recovery for method" method=method.name MINIMUM_CHANNEL_SIZE

            data = bitstring(decode(method, packet))
            if length(data) >= MINIMUM_CHANNEL_SIZE + 12 && data[1:MINIMUM_CHANNEL_SIZE] == bitstring(SENTINEL)[end-MINIMUM_CHANNEL_SIZE+1:end]
                offset = parse(UInt8, data[MINIMUM_CHANNEL_SIZE+1:MINIMUM_CHANNEL_SIZE+8], base=2)
                transmission_length = parse(Int, data[MINIMUM_CHANNEL_SIZE+9:MINIMUM_CHANNEL_SIZE+12], base=2)
                @warn "Recovery packet detected" o=offset tl=transmission_length
                for (length, integrity) ∈ reverse(integrities)[1:min(end, 4)] # Go back max 4 integrities, to be safe
                    @debug "Checking integrity" li=(length, integrity) length % 0x1f
                    if length % 0x10 == transmission_length - 1 # The -1 is an artefact of the pointer on the sender side
                        ARP_Beacon(integrity ⊻ offset, IPv4Addr(get_local_ip()))
                        return i
                    end
                end
            end
        end
    end
    return -1 # Not a recovery packet
end


function process_meta(data::String)::Tuple{Symbol, Any}
    meta = data[1:MINIMUM_CHANNEL_SIZE]
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

import Base: -, >
function -(a::Tuple{Float64, Int64}, b::Tuple{Float64, Int64})::Tuple{Float64, Int64}
    return (a[1] - b[1], a[2] - b[2])
end
function >(a::Tuple{Float64, Int64}, b::Tuple{Float64, Int64})::NTuple{2, Bool}
    return (a[1] > b[1], a[2] > b[2])
end


function listen(queue::Channel{Packet}, methods::Vector{covert_method})::Vector{UInt8}
    # Listen for sentinel
    local_ip = get_local_ip()
    previous = ""
    data = ""
    chunk = ""
    sentinel_recieved = false
    current_method = methods[1]
    packets = 0
    integrities = Vector{Tuple{Int, UInt8}}() # (transimission_length, integrity)
    last_interval_size = Tuple{Float64, Int64}[(0.0, 0)]
    last_interval_point = Tuple{Float64, Int64}[(0.0, 0)]
    @debug "Listening for sentinel" current_method.name
    while true
        current_point = Tuple{Float64, Int64}[(time(), packets)]
        recovery = any(((current_point .- last_interval_point) .> last_interval_size)[1])
        packet = take!(queue)
        type, kwargs = process_packet(current_method, packet)
        if recovery && type != :method_change
            index = try_recover(packet, integrities, methods)
            if index != -1
                @info "Recovering to new method" method=methods[index].name
                current_method = methods[index]
                last_interval_point = current_point
                continue
                # Recovery successful
            end
        end
        if type == :sentinel
            if sentinel_recieved # If we have already recieved a sentinel, we have finished the data
                break
            else
                @info "Sentined recieved, beginning data collection"
                sentinel_recieved = true
            end
            sentinel_recieved = true
        elseif sentinel_recieved && type == :method_change
            (new_method_index, integrity_offset) = kwargs
            @info "Preparing for method change" new_method_index
            open("recv.log", "w") do io
                write(io, chunk)
            end
            integrity = integrity_check(chunk)
            # Beacon out integrity of chunk
            ARP_Beacon(integrity ⊻ integrity_offset, IPv4Addr(local_ip))
            current_method = methods[new_method_index]
            previous = data
            data *= chunk
            chunk = ""
            push!(integrities, (length(data), integrity))
            last_interval_size = current_point .- last_interval_point
            last_interval_point = current_point
        elseif sentinel_recieved && type == :integrity_fail
            @warn "Integrity check failed of last chunk, reverting..."
            chunk = ""
            pop!(integrities) # Remove last integrity, it was wrong...
            data = previous # Revert 'commit' of chunk
        
        elseif sentinel_recieved && type == :data
            @debug "Data received, adding to chunk" chunk_length=length(chunk) total_length=length(data) data=kwargs
            chunk *= kwargs
            packets += 1
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
        @info "Communication stream finished, writing to file" file=file
        open(file, "w") do io
            write(io, data)
        end
    end
end
