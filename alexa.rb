require 'active_support/inflector'
require "active_support/core_ext/hash"

AWS_CONFIG = {
  aws_access_key_id: ENV['AWS_ACCESS_KEY_ID'],
  aws_secret_key: ENV['AWS_SECRET_KEY']
}
ALEXA_DOMAIN = ENV['ALEXA_DOMAIN']

module Amazon
  class Awis
    AWIS_DOMAIN = 'awis.amazonaws.com'

    # Converts a hash into a query string (e.g. {a => 1, b => 2} becomes "a=1&b=2")
    def self.escape_query(query)
      query.to_a.sort_by(&:first).map { |item| item.first + '=' + CGI::escape(item.last.to_s) }.join('&')
    end

    def self.prepare_url(domain, options)
      timestamp_now = Time.now.utc.iso8601

      params = {
        'AWSAccessKeyId' => options[:aws_access_key_id],
        'Action' => 'UrlInfo',
        'ResponseGroup' => 'TrafficData',
        'SignatureMethod' => 'HmacSHA256',
        'SignatureVersion' => 2,
        'Timestamp' => timestamp_now,
        'Url' => domain
      }

      signature = Base64.encode64(
        OpenSSL::HMAC.digest(
          'sha256', options[:aws_secret_key],
          "GET\n#{AWIS_DOMAIN}\n/\n" + escape_query(params).strip
        )
      ).chomp
      query = escape_query(params.merge('Signature' => signature))

      URI.parse "http://#{AWIS_DOMAIN}/?#{query}"
    end

    def self.traffic_data(domain, options)
      url = self.prepare_url(domain, options)

      res = Net::HTTP.get_response(url)
      unless res.kind_of? Net::HTTPSuccess
        raise "HTTP Response: #{res.code} #{res.message} #{res.body}"
      end

      Hash.from_xml(res.body)
    end
  end
end

begin
  data = Amazon::Awis.traffic_data(ALEXA_DOMAIN, AWS_CONFIG)
  ranks = data['UrlInfoResponse']['Response']['UrlInfoResult']['Alexa']['TrafficData']['UsageStatistics']['UsageStatistic']

  rv = [0, 2].inject('') do |acc, i|
    rank = ranks[i]

    delta = rank['Rank']['Delta'].to_i
    delta = (delta.abs == delta ? "(-#{delta.abs}) :red_circle::-1:" : "(+#{delta.abs}) :four_leaf_clover::+1:") # negative delta is up, according to web?

    period = rank['TimeRange']
    period = "#{period.values.first} #{period.keys.first.downcase.singularize} avg."

    acc += "#{ALEXA_DOMAIN} Alexa global rank: #{rank['Rank']['Value']} #{delta} (#{period})\n"
  end
  puts rv
rescue Exception => e
  puts "Alexa rank request failed, sorry. (#{e.message})"
end

