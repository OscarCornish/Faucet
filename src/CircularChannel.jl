# Define a "CircularChannel", a thread-safe channel, that will overwrite the oldest data when full
# Heavily inspired by:
# https://github.com/JuliaCollections/DataStructures.jl/blob/master/src/circular_buffer.jl

"""
    CircularChannel{T}(sz::Int) where T
```
A thread-safe channel, that will overwrite the oldest data when full
Implements:
    - put!(cc::CircularChannel{T}, data::T)
    - take!(cc::CircularChannel{T})::T
    - length(cc::CircularChannel{T})::Int
    - size(cc::CircularChannel{T})::Tuple{Int}
    - isempty(cc::CircularChannel{T})::Bool
    - convert(::Vector{T}, cc::CircularChannel{T})::Vector{T}
```
"""
mutable struct CircularChannel{T} <: AbstractVector{T}
    capacity::Int
    @atomic first::Int
    @atomic length::Int
    buffer::Vector{T}
    lock::Threads.Condition

    function CircularChannel{T}(first::Int, len::Int, buf::Vector{T}) where {T}
        first <= length(buf) && len <= length(buf) || error("Value of 'length' and 'first' must be in the buffers bounds")
        return new{T}(length(buf), first, len, buf, Threads.Condition())
    end
end

# Short hand
CircularChannel{T}(sz::Int) where T = CircularChannel{T}(1, 0, Vector{T}(undef, sz))

# Check bounds
Base.@propagate_inbounds function _buffer_index_checked(cc::CircularChannel, i::Int)
    @boundscheck if i < 1 || i > cc.length
        throw(BoundError(cc, i))
    end
    _buffer_index(cc, i)
end

# Implement the "circular" functionality
@inline function _buffer_index(cc::CircularChannel, i::Int)
    n = cc.capacity
    idx = cc.first + i - 1
    return ifelse(idx > n, idx - n, idx)
end

# Get index and set index are only intended for internal use, only "supported" functions are put! and coverting to a vector

# Override getindex to use our circular functionality
@inline Base.@propagate_inbounds function Base.getindex(cc::CircularChannel, i::Int)
    @lock cc.lock return cc.buffer[_buffer_index_checked(cc, i)]
end

# Override setindex to use our circular functionality
@inline Base.@propagate_inbounds function Base.setindex(cc::CircularChannel, data, i::Int)
    @lock cc.lock cc.buffer[_buffer_index_checked(cc, i)] = data && return cc
end

@inline function Base.put!(cc::CircularChannel{T}, data) where T
    lock(cc.lock)
    try
        data_converted = convert(T, data)
        if cc.length == cc.capacity
            @atomic cc.first = (cc.first == cc.capacity ? 1 : cc.first + 1)
        else
            @atomic cc.length += 1
        end
        @inbounds cc.buffer[_buffer_index(cc, cc.length)] = data_converted
        notify(cc.lock)
        return cc
    finally
        unlock(cc.lock)
    end
end

@inline function Base.take!(cc::CircularChannel{T}) where T
    lock(cc.lock)
    try
        if cc.length == 0
            wait(cc.lock)
        end
        @atomic cc.length -= 1
        return cc.buffer[_buffer_index(cc, cc.length + 1)]
    finally
        unlock(cc.lock)
    end
end

# Define some generic functions
Base.length(cc::CircularChannel) = @atomic cc.length
Base.size(cc::CircularChannel) = (length(cc), )
Base.isempty(cc::CircularChannel) = length(cc) == 0

# Extract the data from the channel, in order
function Base.convert(::Vector{T}, cc::CircularChannel{T}) where T
    lock(cc.lock)
    try
        first = cc.buffer[cc.first:cc.length]
        second = cc.buffer[1:cc.first-1]
        return Vector{T}[first; second]
    finally
        unlock(cc.lock)
    end
end
