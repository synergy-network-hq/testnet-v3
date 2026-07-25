#!/usr/bin/env ruby

require "json"
require "optparse"
require "yaml"

options = {}
OptionParser.new do |parser|
  parser.banner = "Usage: validate_observability.rb --manifest FILE --config FILE --rules DIR [--plan]"
  parser.on("--manifest FILE") { |value| options[:manifest] = value }
  parser.on("--config FILE") { |value| options[:config] = value }
  parser.on("--rules DIR") { |value| options[:rules] = value }
  parser.on("--plan") { options[:plan] = true }
end.parse!

missing = %i[manifest config rules].reject { |key| options.key?(key) }
abort("missing options: #{missing.join(", ")}") unless missing.empty?

def fail_check(message)
  warn "ERROR: #{message}"
  exit 1
end

def require_key(hash, key, context)
  fail_check("#{context} is missing #{key}") unless hash.is_a?(Hash) && hash.key?(key)
  hash.fetch(key)
end

def expect(condition, message)
  fail_check(message) unless condition
end

begin
  manifest = JSON.parse(File.read(options[:manifest]))
rescue StandardError => e
  fail_check("cannot parse manifest #{options[:manifest]}: #{e.message}")
end

begin
  config = YAML.safe_load(File.read(options[:config]), aliases: false)
rescue StandardError => e
  fail_check("cannot parse Prometheus YAML #{options[:config]}: #{e.message}")
end

expect(manifest["schema_version"] == 1, "unsupported proxy contract schema")
expect(manifest["environment"] == "testnet", "proxy contract environment must be testnet")
expect(manifest["network"] == "synergy-testnet", "proxy contract network must be synergy-testnet")
expect(manifest["chain_id"] == "1264", "proxy contract chain_id must be 1264")
policy = require_key(manifest, "policy", "manifest")
expect(policy["observer_outside_validator_vpn"] == true, "observer must be outside the validator VPN")
expect(policy["validator_telemetry_via_relayers_only"] == true, "validator telemetry must use relayers")
expect(policy["public_service_nodes_must_not_dial_validator_innernet"] == true,
       "public service nodes must not dial validator Innernet")

observer = require_key(manifest, "observer", "manifest")
expect(observer["prometheus_config_destination"] == "/opt/prometheus/config/prometheus.yml",
       "observer Prometheus destination drifted")
expect(observer["rules_destination"] == "/opt/prometheus/config/rules",
       "observer rules destination drifted")
expect(observer["service"] == "prometheus.service", "observer Prometheus service drifted")

relayers = require_key(manifest, "relayers", "manifest")
expect(relayers.length == 3, "proxy contract must define exactly three relayers")
expect(relayers.map { |relayer| relayer["id"] }.sort == %w[relayer-1 relayer-2 relayer-3],
       "relayer IDs must be relayer-1 through relayer-3")

jobs = require_key(config, "scrape_configs", "Prometheus config")
job_map = jobs.each_with_object({}) { |job, result| result[job.fetch("job_name")] = job }
expected_jobs = %w[
  synergy-observer synergy-posy-exporter synergy-validators synergy-rpc-gateway
  synergy-explorer-indexer synergy-archive node_exporter node_exporter_public
  synergy-qrpc-probes synergy-http-probes synergy-bootstrap-probes prometheus
]
expect((expected_jobs - job_map.keys).empty?, "Prometheus config is missing canonical jobs")
expect(job_map.keys.uniq.length == job_map.keys.length, "Prometheus config contains duplicate job names")
expect(Array(config["rule_files"]).include?("/opt/prometheus/config/rules/*.yml"),
       "Prometheus config must load /opt/prometheus/config/rules/*.yml")

rule_files = Dir[File.join(options[:rules], "*.yml")].sort
expect(rule_files.length == 2, "expected exactly two observer rule files")
rule_files.each do |path|
  begin
    YAML.safe_load(File.read(path), aliases: false)
  rescue StandardError => e
    fail_check("cannot parse rule file #{path}: #{e.message}")
  end
end

entries = []
jobs.each do |job|
  Array(job["static_configs"]).each do |group|
    labels = group["labels"] || {}
    Array(group["targets"]).each do |target|
      entries << {"job" => job.fetch("job_name"), "target" => target, "labels" => labels}
    end
  end
end

expect(entries.none? { |entry| entry["target"].include?("10.70.10.") },
       "Prometheus must never dial a validator Innernet address directly")
retired_innernet_prefix = ["10", "69"].join(".") + "."
expect(entries.none? { |entry| entry["target"].include?(retired_innernet_prefix) },
       "retired private target found in Prometheus config")

def target_entries(entries, job, target)
  entries.select { |entry| entry["job"] == job && entry["target"] == target }
end

def expect_target(entries, job, target, expected_labels)
  matches = target_entries(entries, job, target)
  expect(matches.length == 1, "expected exactly one #{job} target #{target}, found #{matches.length}")
  labels = matches.fetch(0)["labels"]
  expected_labels.each do |key, value|
    expect(labels[key] == value, "#{job} #{target} label #{key}=#{labels[key].inspect}, expected #{value.inspect}")
  end
end

validator_entries = entries.select { |entry| entry["labels"]["role"] == "validator" }
expect(validator_entries.length == 18, "expected six validators across app, exporter, and qRPC routes")

seen_validator_ids = []
relayers.each do |relayer|
  relayer_id = relayer.fetch("id")
  relayer_dns = relayer.fetch("public_dns")
  relayer_ip = relayer.fetch("canonical_innernet")
  expected_relayer_ip = "10.70.20.#{relayer_id.delete_prefix("relayer-")}"
  expect(relayer_ip == expected_relayer_ip, "#{relayer_id} Innernet address must be #{expected_relayer_ip}")

  direct = relayer.fetch("direct_telemetry")
  expect(direct == {"node_exporter" => 9100, "read_proxy" => 15640},
         "#{relayer_id} direct telemetry ports drifted")
  expect_target(entries, "node_exporter", "#{relayer_dns}:9100",
                "role" => "relayer", "node" => relayer_id, "telemetry_path" => "public",
                "canonical_innernet" => relayer_ip)
  expect_target(entries, "synergy-qrpc-probes", "#{relayer_dns}:15640",
                "role" => "relayer", "node" => relayer_id, "telemetry_path" => "restricted-public-proxy",
                "canonical_innernet" => relayer_ip)

  validators = relayer.fetch("validators")
  expect(validators.length == 2, "#{relayer_id} must proxy exactly two validators")
  validators.each do |validator|
    validator_id = validator.fetch("id")
    seen_validator_ids << validator_id
    expected_validator_ip = "10.70.10.#{validator_id.delete_prefix("validator-")}"
    expect(validator.fetch("canonical_innernet") == expected_validator_ip,
           "#{validator_id} Innernet address must be #{expected_validator_ip}")
    expect(validator.fetch("backend_ports") == {"app_metrics" => 6030, "qrpc" => 5640, "node_exporter" => 9100},
           "#{validator_id} backend telemetry ports drifted")

    proxy = validator.fetch("proxy_ports")
    path = "#{relayer_id}-proxy"
    labels = {
      "role" => "validator",
      "node" => validator_id,
      "telemetry_path" => path,
      "canonical_innernet" => expected_validator_ip
    }
    expect_target(entries, "synergy-validators", "#{relayer_dns}:#{proxy.fetch("app_metrics")}", labels)
    expect_target(entries, "node_exporter", "#{relayer_dns}:#{proxy.fetch("node_exporter")}", labels)
    expect_target(entries, "synergy-qrpc-probes", "#{relayer_dns}:#{proxy.fetch("qrpc")}", labels)
  end
end

expect(seen_validator_ids.sort == (1..6).map { |number| "validator-#{number}" },
       "proxy contract must cover validators 1 through 6 exactly once")
expect(validator_entries.all? { |entry| entry["target"].start_with?("relay") },
       "every validator target must use a relayer hostname")

puts "validated observer Prometheus config, #{relayers.length} relayers, 6 validator proxy routes, and #{rule_files.length} rule files"

if options[:plan]
  puts "observer: outside-validator-vpn -> #{observer.fetch("prometheus_config_destination")}"
  relayers.each do |relayer|
    relayer.fetch("validators").each do |validator|
      proxy = validator.fetch("proxy_ports")
      backend = validator.fetch("backend_ports")
      puts "#{relayer.fetch("id")}: #{relayer.fetch("public_dns")}:#{proxy.fetch("app_metrics")} -> #{validator.fetch("canonical_innernet")}:#{backend.fetch("app_metrics")} app_metrics"
      puts "#{relayer.fetch("id")}: #{relayer.fetch("public_dns")}:#{proxy.fetch("qrpc")} -> #{validator.fetch("canonical_innernet")}:#{backend.fetch("qrpc")} qrpc"
      puts "#{relayer.fetch("id")}: #{relayer.fetch("public_dns")}:#{proxy.fetch("node_exporter")} -> #{validator.fetch("canonical_innernet")}:#{backend.fetch("node_exporter")} node_exporter"
    end
  end
  puts "apply: not performed by this tool; use an approved deployment workflow after review"
end
