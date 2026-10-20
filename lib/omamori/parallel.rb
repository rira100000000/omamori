# frozen_string_literal: true

module Omamori
  # Minimal thread pool: maps items with at most `concurrency` threads, keeping order.
  module Parallel
    def self.map(items, concurrency)
      queue = Queue.new
      items.each_with_index { |item, index| queue << [item, index] }
      results = Array.new(items.size)
      workers = Array.new([concurrency, items.size].min) do
        Thread.new do
          loop do
            item, index = queue.pop(true)
            results[index] = yield(item)
          end
        rescue ThreadError
          # queue is empty
        end
      end
      workers.each(&:join)
      results
    end
  end
end
