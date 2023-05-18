using AES
using Dates
import Base: -, >

# These functions are to remove bulky lines from the listen function
function -(a::Tuple{Float64, Int64}, b::Tuple{Float64, Int64})::Tuple{Float64, Int64}
    # (a[1] - b[1], a[2] - b[2]) => a - b
    return (a[1] - b[1], a[2] - b[2])
end
function >(a::Tuple{Float64, Int64}, b::Tuple{Float64, Int64})::NTuple{2, Bool}
    # (a[1] > b[1], a[2] > b[2]) => a > b
    return (a[1] > b[1], a[2] > b[2])
end

"""
    dec(data::bitstring)::Vector{UInt8}

Decode a packet using Pre-shared key
 & removing padding
"""
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

"""
```markdown
Initialise our receiver:
- `:local` => Filter to only local traffic
- `:all` => Filter to all traffic
```
"""
function init_receiver(bpf_filter::Union{String, Symbol})::CircularChannel{Packet}
    if bpf_filter == :local
        bpf_filter = local_bound_traffic()
    end
    if bpf_filter == :all
        bpf_filter = ""
    end
    @debug "Initializing receiver" filter=bpf_filter
    if typeof(bpf_filter) != String
        throw(ArgumentError("bpf_filter must be a string, :local, or :all"))
    end
    return init_queue(;bpf_filter_string=bpf_filter)
end

"""
Check a packet against all methods, if it matches the format of a method, return the index of the method, else return -1
This check uses the last know verification point, something that both sides know.
"""
function try_recover(packet::Packet, integrities::Vector{Tuple{Int, UInt8}}, methods::Vector{covert_method})::Tuple{Int64, Int64}
    for (i, method) ∈ enumerate(methods)
        if couldContainMethod(packet, method)
            data = bitstring(decode(method, packet))
            if length(data) >= MINIMUM_CHANNEL_SIZE + 12 && data[1:MINIMUM_CHANNEL_SIZE] == bitstring(SENTINEL)[end-MINIMUM_CHANNEL_SIZE+1:end]
                offset = parse(UInt8, data[MINIMUM_CHANNEL_SIZE+1:MINIMUM_CHANNEL_SIZE+8], base=2)
                transmission_length = parse(Int, data[MINIMUM_CHANNEL_SIZE+9:MINIMUM_CHANNEL_SIZE+12], base=2)
                for (len, integrity) ∈ reverse(integrities)[1:min(end, 4)] # Go back max 4 integrities, to be safe
                    if len % 0x10 == transmission_length - 1 # The -1 is an artefact of the pointer on the sender side
                        ARP_Beacon(integrity ⊻ offset, IPv4Addr(get_local_ip()))
                        return i, len
                    end
                end
            end
        end
    end
    return -1, 0 # Not a recovery packet
end

"""
Process a packet contain meta protocols
"""
function process_meta(data::String)::Tuple{Symbol, Any}
    meta = data[1:MINIMUM_CHANNEL_SIZE]
    if meta == bitstring(SENTINEL)[end-MINIMUM_CHANNEL_SIZE+1:end]
        return (:sentinel, nothing)
    elseif meta == bitstring(DISCARD_CHUNK)[end-MINIMUM_CHANNEL_SIZE+1:end]
        return (:integrity_fail, data[MINIMUM_CHANNEL_SIZE+1:end])
    else # Return 
        return (:method_change, extract_method(data))
    end
end
    
"""
Process a packet, returning the type of packet, and the data
"""
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

"""
Await a covert communication, and return the decrypted data
"""
function listen(queue::CircularChannel{Packet}, methods::Vector{covert_method})::Vector{UInt8}
    local_ip = get_local_ip()
    # previous is essentially a revert, if a commited chunks integrity fails, we can revert to the previous state
    data, previous, chunk = "", "", ""
    # Track if we have recieved a sentinel
    sentinel_recieved = false
    # Default to the first method
    current_method = methods[begin]
    # Keep track of the number of packets recieved
    packets = 0

    # Recovery variables
    # (transimission_length, integrity)
    integrities = Vector{Tuple{Int, UInt8}}()
    last_interval_size = Tuple{Float64, Int64}[(0.0, 0)]
    last_interval_point = Tuple{Float64, Int64}[(0.0, 0)]

    # Await sentinel
    @debug "Listening for sentinel" current_method.name
    while true
        current_point = Tuple{Float64, Int64}[(time(), packets)]
        # Take a packet from the queue, to process it
        packet = take!(queue)
        
        # If we have exceeded the size of the last interval (by packets or time), we should 
        recovery = any(((current_point .- last_interval_point) .> last_interval_size)[1])
        
        # Process the packet, using our current method
        type, kwargs = process_packet(current_method, packet)

        # If we are in recovery mode, and the packet is not a method change (verification)
        if recovery && type != :method_change
            # Try to recover to a new method
            (index, len) = try_recover(packet, integrities, methods)
            if index != -1
                # Recovery successful, reset the current chunk
                chunk = ""
                # Remove data past the last valid recovery point (senders POV)
                data = data[1:len]
                @info "Recovering to new method" method=methods[index].name
                
                # Update current method
                current_method = methods[index]
                # Change time of last interval, but don't update the size (recovery)
                last_interval_point = current_point
                # Don't process this packet any further (it could poison our chunk)
                continue
            end
        end

        # Check for sentinel
        if type == :sentinel
            if sentinel_recieved # If we have already recieved a sentinel, we have finished the data
                break
            end
            @info "Sentined recieved, beginning data collection"
            sentinel_recieved = true

        # We put sentinel_recieved check first to fail fast
        elseif sentinel_recieved && type == :method_change
            (new_method_index, integrity_offset) = kwargs
            @debug "Preparing for method change" new_method_index
            
            # On method change we confirm the integrity of the chunk, so get it
            integrity = integrity_check(chunk)

            # Beacon out integrity of chunk ⊻'d against the offset we received
            ARP_Beacon(integrity ⊻ integrity_offset, IPv4Addr(local_ip))
            
            # Update current method
            current_method = methods[new_method_index]

            # Save our old data, incase this integrity is wrong
            previous = data

            # Append chunk to data
            data *= chunk
            # Reset chunk
            chunk = ""

            # Update integrity list
            push!(integrities, (length(data), integrity))
            # Update last interval size
            last_interval_size = current_point .- last_interval_point
            # Update last interval point
            last_interval_point = current_point
        
        elseif sentinel_recieved && type == :integrity_fail
            @warn "Integrity check failed of last chunk, reverting..."
            # Reset the chunk, and add the data that follows this metaprotocol
            chunk = kwargs
            # Remove last integrity, it was wrong...
            pop!(integrities)
            # Revert 'commit' of chunk
            data = previous
        
        elseif sentinel_recieved && type == :data
            @debug "Data received, adding to chunk" chunk_length=length(chunk) total_length=length(data) data=kwargs
            # Append data to chunk
            chunk *= kwargs
            # Increment packets
            packets += 1
        end
    end
    # Append remaining chunk to data (Should be empty due to post-payload verification)
    data *= chunk
    @debug "Data collection complete, decrypting..."
    return dec(data)
end

"""
Listen forever will repeatedly call [`listen`](@ref) on the given queue, and write the data to a unique file
"""
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
