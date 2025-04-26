# frozen_string_literal: true

module Omamori
  module AIAnalysisEngine
    class DiffSplitter
      # TODO: Determine appropriate chunk size based on token limits
      # Gemini 1.5 Pro has a large context window (1 million tokens),
      # but splitting might still be necessary for very large inputs
      # or to manage cost/latency.
      DEFAULT_CHUNK_SIZE = 8000 # Characters as a proxy for tokens

      def initialize(chunk_size: DEFAULT_CHUNK_SIZE)
        @chunk_size = chunk_size
      end

      def split(content)
        chunks = []
        current_chunk = ""
        content.each_line do |line|
          if (current_chunk.length + line.length) > @chunk_size
            chunks << current_chunk unless current_chunk.empty?
            current_chunk = line
          else
            current_chunk += line
          end
        end
        chunks << current_chunk unless current_chunk.empty?
        chunks
      end

      def process_in_chunks(content, gemini_client, json_schema, prompt_manager, risks_to_check, model: "gemini-1.5-pro-latest")
        all_results = []
        chunks = split(content)

        puts "Splitting content into #{chunks.size} chunks..."

        chunks.each_with_index do |chunk, index|
          puts "Processing chunk #{index + 1}/#{chunks.size}..."
          prompt = prompt_manager.build_prompt(chunk, risks_to_check)
          result = gemini_client.analyze(prompt, json_schema, model: model)
          all_results << result if result
          # TODO: Handle potential rate limits or errors between chunks
        end

        # TODO: Combine results from all chunks
        combine_results(all_results)
      end

      private

      def combine_results(results)
        # This is a placeholder. Combining results from multiple AI responses
        # requires careful consideration of overlapping findings, context, etc.
        # For now, just flatten the list of security risks.
        combined_risks = results.flat_map do |result|
          result && result["security_risks"] ? result["security_risks"] : []
        end
        { "security_risks" => combined_risks }
      end
    end
  end
end