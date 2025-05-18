# frozen_string_literal: true

require 'spec_helper'
require 'pathname'
require 'omamori/report_generator/html_formatter'

RSpec.describe Omamori::ReportGenerator::HTMLFormatter do
  let(:output_path_prefix) { './reports' }
  let(:template_path) { '/fake/path/to/report_template.erb' }
  let(:erb_template_double) { instance_double(ERB) }
  let(:combined_results) do
    {
      'ai_security_risks' => [{ 'type' => 'XSS', 'severity' => 'High' }],
      'static_analysis_results' => { 'brakeman' => { 'warnings' => [] } }
    }
  end
  let(:rendered_html) { '<html><body>Report Content</body></html>' }

  let(:project_root) do
    Pathname.new(__dir__).join('..', '..', '..').expand_path
  end
  let(:actual_template_path) { File.join(project_root, 'lib', 'omamori', 'report_generator', 'report_template.erb') }

  before do
    # Mock File.read for the template file
    allow(File).to receive(:read).with(template_path).and_return('<%= @ai_risks %> <%= @static_results %>')
    allow(File).to receive(:read).with(actual_template_path).and_return('<%= @ai_risks %> <%= @static_results %>')

    # Mock ERB.new
    allow(ERB).to receive(:new).and_return(erb_template_double)

    # Mock template.result
    allow(erb_template_double).to receive(:result).and_return(rendered_html)
  end

  describe '#initialize' do
    it 'initializes with the provided output_path_prefix' do
      formatter = Omamori::ReportGenerator::HTMLFormatter.new(output_path_prefix)
      expect(formatter.instance_variable_get(:@output_path_prefix)).to eq(output_path_prefix)
    end

    it 'initializes with the default template path if none is provided' do
      default_template = actual_template_path
      expect(File).to receive(:read).with(default_template).and_return('') # Ensure default is read
      formatter = Omamori::ReportGenerator::HTMLFormatter.new(output_path_prefix)
      expect(formatter.instance_variable_get(:@template_path)).to eq(default_template)
    end

    it 'initializes with the provided template path' do
      expect(File).to receive(:read).with(template_path).and_return('') # Ensure provided path is read
      formatter = Omamori::ReportGenerator::HTMLFormatter.new(output_path_prefix, template_path)
      expect(formatter.instance_variable_get(:@template_path)).to eq(template_path)
    end

    it 'raises an error if the template file is not found' do
      allow(File).to receive(:read).with(template_path).and_raise(Errno::ENOENT)
      expect do
        Omamori::ReportGenerator::HTMLFormatter.new(output_path_prefix, template_path)
      end.to raise_error("HTML template file not found at #{template_path}")
    end
  end

  describe '#format' do
    let(:formatter) { Omamori::ReportGenerator::HTMLFormatter.new(output_path_prefix, template_path) }

    it 'assigns ai_security_risks and static_analysis_results to instance variables' do
      formatter.format(combined_results)
      expect(formatter.instance_variable_get(:@ai_risks)).to eq(combined_results['ai_security_risks'])
      expect(formatter.instance_variable_get(:@static_results)).to eq(combined_results['static_analysis_results'])
    end

    it 'assigns empty array/hash if keys are missing or nil in combined_results' do
      formatter.format({})
      expect(formatter.instance_variable_get(:@ai_risks)).to eq([])
      expect(formatter.instance_variable_get(:@static_results)).to eq({})

      formatter.format({ 'ai_security_risks' => nil, 'static_analysis_results' => nil })
      expect(formatter.instance_variable_get(:@ai_risks)).to eq([])
      expect(formatter.instance_variable_get(:@static_results)).to eq({})
    end

    it 'calls result on the ERB template with the correct binding' do
      # We can't directly check the binding content easily, but we can check that result is called
      # on the mocked template instance. The instance variables set in format should be available
      # in the binding when result is called.
      expect(erb_template_double).to receive(:result).with(instance_of(Binding))
      formatter.format(combined_results)
    end

    it 'returns the result of the ERB template evaluation' do
      expect(formatter.format(combined_results)).to eq(rendered_html)
    end

    it 'handles Errno::ENOENT during template evaluation' do
      allow(erb_template_double).to receive(:result).and_raise(Errno::ENOENT)
      expect(formatter.format(combined_results)).to eq('Error: HTML template file not found.')
    end

    it 'handles other errors during template evaluation' do
      error_message = 'Something went wrong during ERB evaluation'
      allow(erb_template_double).to receive(:result).and_raise(StandardError, error_message)
      expect(formatter.format(combined_results)).to eq("Error generating HTML report: #{error_message}")
    end
  end
end
