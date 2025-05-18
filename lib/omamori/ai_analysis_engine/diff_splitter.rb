# lib/omamori/ai_analysis_engine/diff_splitter.rb

module Omamori
  module AIAnalysisEngine
    class DiffSplitter
      DEFAULT_CHUNK_SIZE = 8000 # Characters as a proxy for tokens

      def initialize(chunk_size: DEFAULT_CHUNK_SIZE)
        @chunk_size = chunk_size
      end

      def split(content)
        chunks = []
        current_chunk = ""
        content.each_line do |line|
          if (current_chunk.length + line.length) > @chunk_size && !current_chunk.empty?
            chunks << current_chunk
            current_chunk = line
          else
            current_chunk += line
          end
        end
        chunks << current_chunk unless current_chunk.empty?
        chunks
      end

      # Updated to accept file_path keyword argument
      def process_in_chunks(content, gemini_client, json_schema, prompt_manager, risks_to_check, model: "gemini-1.5-pro-latest", file_path: nil)
        all_results = []
        chunks = split(content)

        puts "[DEBUG Omamori DiffSplitter] Splitting content into #{chunks.size} chunks for file: #{file_path || 'N/A'}"

        chunks.each_with_index do |chunk, index|
          puts "[DEBUG Omamori DiffSplitter] Processing chunk #{index + 1}/#{chunks.size} for file: #{file_path || 'N/A'}"
          # Pass file_path (potentially modified for chunks) to build_prompt
          chunk_file_path_info = if file_path
                                   chunks.size > 1 ? "#{file_path} (chunk #{index + 1}/#{chunks.size})" : file_path
                                 end
          prompt = prompt_manager.build_prompt(chunk, risks_to_check, json_schema, file_path: chunk_file_path_info)
          result = gemini_client.analyze(prompt, json_schema, model: model) # This call to analyze is correct
          all_results << result
        end
        combine_results(all_results)
      end

      private

      def combine_results(results)
        combined_risks = results.flat_map do |result|
          result && result["security_risks"] ? result["security_risks"] : []
        end
        { "security_risks" => combined_risks }
      end
    end
  end
end
